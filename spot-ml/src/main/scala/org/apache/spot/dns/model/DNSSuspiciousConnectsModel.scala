package org.apache.spot.dns.model

import org.apache.spark.SparkContext
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types._
import org.apache.spark.sql.{DataFrame, Row, SQLContext}
import org.apache.spot.SpotLDACWrapper
import org.apache.spot.SpotLDACWrapper.{SpotLDACInput, SpotLDACOutput}
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.dns.DNSSchema._
import org.apache.spot.dns.DNSWordCreation
import org.apache.spot.utilities.{CountryCodes, DomainProcessor, Quantiles, TopDomains}
import org.apache.spot.utilities.DomainProcessor.DomainInfo
import org.apache.log4j.Logger


/**
  * A probabilistic model of the DNS queries issued by each client IP.
  *
  * The model uses a topic-modelling approach that:
  * 1. Simplifies DNS log entries into words.
  * 2. Treats the DNS queries of each client into a collection of words.
  * 3. Decomposes common query behaviors using a collection of "topics" that represent common profiles
  * of query behavior. These "topics" are probability distributions on words.
  * 4. Each client IP has a mix of topics corresponding to its behavior.
  * 5. Query probability at IP is estimated by simplifying query into word, and then
  * combining the word probabilities per topic using the topic mix of the particular IP.
  *
  * Create these models using the  factory in the companion object.
  *
  * @param inTopicCount          Number of topics to use in the topic model.
  * @param inIpToTopicMix        Per-IP topic mix.
  * @param inWordToPerTopicProb  Per-word,  an array of probability of word given topic per topic.
  * @param inTimeCuts            Quantile cut-offs for discretizing the time of day in word construction.
  * @param inFrameLengthCuts     Quantile cut-offs for discretizing the frame length in word construction.
  * @param inSubdomainLengthCuts Quantile cut-offs for discretizing subdomain length in word construction.
  * @param inNumberPeriodsCuts   Quantile cut-offs for discretizing domain number-of-periods count in word construction.
  * @param inEntropyCuts         Quantile cut-offs for discretizing the subdomain entropy in word construction.
  */
class DNSSuspiciousConnectsModel(inTopicCount: Int,
                                 inIpToTopicMix: Map[String, Array[Double]],
                                 inWordToPerTopicProb: Map[String, Array[Double]],
                                 inTimeCuts: Array[Double],
                                 inFrameLengthCuts: Array[Double],
                                 inSubdomainLengthCuts: Array[Double],
                                 inNumberPeriodsCuts: Array[Double],
                                 inEntropyCuts: Array[Double]) {

  val topicCount = inTopicCount
  val ipToTopicMix = inIpToTopicMix
  val wordToPerTopicProb = inWordToPerTopicProb
  val timeCuts = inTimeCuts
  val frameLengthCuts = inFrameLengthCuts
  val subdomainLengthCuts = inSubdomainLengthCuts
  val numberPeriodsCuts = inNumberPeriodsCuts
  val entropyCuts = inEntropyCuts

  /**
    * Use a suspicious connects model to assign estimated probabilities to a dataframe of
    * DNS log events.
    *
    * @param sc         Spark Context
    * @param sqlContext Spark SQL context
    * @param inDF       Dataframe of DNS log events, containing at least the columns of [[DNSSuspiciousConnectsModel.ModelSchema]]
    * @return Dataframe with a column named [[org.apache.spot.dns.DNSSchema.Score]] that contains the
    *         probability estimated for the network event at that row
    */
  def score(sc: SparkContext, sqlContext: SQLContext, inDF: DataFrame): DataFrame = {

    val countryCodesBC = sc.broadcast(CountryCodes.CountryCodes)
    val topDomainsBC = sc.broadcast(TopDomains.TopDomains)
    val ipToTopicMixBC = sc.broadcast(ipToTopicMix)
    val wordToPerTopicProbBC = sc.broadcast(wordToPerTopicProb)


    val scoreFunction =
      new DNSScoreFunction(frameLengthCuts,
        timeCuts,
        subdomainLengthCuts,
        entropyCuts,
        numberPeriodsCuts,
        topicCount,
        ipToTopicMixBC,
        wordToPerTopicProbBC,
        topDomainsBC)


    val scoringUDF = udf((timeStamp: String,
                          unixTimeStamp: Long,
                          frameLength: Int,
                          clientIP: String,
                          queryName: String,
                          queryClass: String,
                          queryType: Int,
                          queryResponseCode: Int) =>
      scoreFunction.score(timeStamp,
        unixTimeStamp,
        frameLength,
        clientIP,
        queryName,
        queryClass,
        queryType,
        queryResponseCode))

    inDF.withColumn(Score, scoringUDF(DNSSuspiciousConnectsModel.modelColumns: _*))
  }
}

/**
  * Contains dataframe schema information as well as the train-from-dataframe routine
  * (which is a kind of factory routine) for [[DNSSuspiciousConnectsModel]] instances.
  *
  */
object DNSSuspiciousConnectsModel {

  val ModelSchema = StructType(List(TimestampField,
    UnixTimestampField,
    FrameLengthField,
    ClientIPField,
    QueryNameField,
    QueryClassField,
    QueryTypeField,
    QueryResponseCodeField))

  val modelColumns = ModelSchema.fieldNames.toList.map(col)

  val DomainStatsSchema = StructType(List(TopDomainField, SubdomainLengthField, SubdomainEntropyField, NumPeriodsField))

  /**
    * Create a new DNS Suspicious Connects model by training it on a data frame and a feedback file.
    *
    * @param sparkContext
    * @param sqlContext
    * @param logger
    * @param config     Analysis configuration object containing CLI parameters.
    *                   Contains the path to the feedback file in config.scoresFile
    * @param inDF       Data used to train the model.
    * @param topicCount Number of topics (traffic profiles) used to build the model.
    * @return A new [[DNSSuspiciousConnectsModel]] instance trained on the dataframe and feedback file.
    */
  def trainNewModel(sparkContext: SparkContext,
                    sqlContext: SQLContext,
                    logger: Logger,
                    config: SuspiciousConnectsConfig,
                    inDF: DataFrame,
                    topicCount: Int): DNSSuspiciousConnectsModel = {

    logger.info("Training DNS suspicious connects model from " + config.inputPath)

    val selectedDF = inDF.select(modelColumns: _*)

    val totalDataDF = selectedDF.unionAll(DNSFeedback.loadFeedbackDF(sparkContext,
      sqlContext,
      config.scoresFile,
      config.duplicationFactor))

    val countryCodesBC = sparkContext.broadcast(CountryCodes.CountryCodes)
    val topDomainsBC = sparkContext.broadcast(TopDomains.TopDomains)


    
    // create quantile cut-offs

    val timeCuts = Quantiles.computeDeciles(totalDataDF.select(UnixTimestamp).rdd.
      map({ case Row(unixTimeStamp: Long) => unixTimeStamp.toDouble }))

    val frameLengthCuts = Quantiles.computeDeciles(totalDataDF.select(FrameLength).rdd
      .map({ case Row(frameLen: Int) => frameLen.toDouble }))

    val domainStatsDF = createDomainStatsDF(sparkContext, sqlContext, countryCodesBC, topDomainsBC, totalDataDF)

    val subdomainLengthCuts = Quantiles.computeQuintiles(domainStatsDF.filter(SubdomainLength + " > 0")
      .select(SubdomainLength).rdd.map({ case Row(subdomainLength: Int) => subdomainLength.toDouble }))

    val entropyCuts = Quantiles.computeQuintiles(domainStatsDF.filter(SubdomainEntropy + " > 0")
      .select(SubdomainEntropy).rdd.map({ case Row(subdomainEntropy: Double) => subdomainEntropy }))

    val numberPeriodsCuts = Quantiles.computeQuintiles(domainStatsDF.filter(NumPeriods + " > 0")
      .select(NumPeriods).rdd.map({ case Row(numberPeriods: Int) => numberPeriods.toDouble }))


    // simplify DNS log entries into "words"

    val dnsWordCreator = new DNSWordCreation(frameLengthCuts, timeCuts, subdomainLengthCuts, entropyCuts, numberPeriodsCuts, topDomainsBC)
    


    val dataWithWordDF = totalDataDF.withColumn(Word, dnsWordCreator.wordCreationUDF(modelColumns: _*))



    // aggregate per-word counts at each IP

    val ipDstWordCounts =
      dataWithWordDF.select(ClientIP, Word).map({ case Row(destIP: String, word: String) => (destIP, word) -> 1 })
        .reduceByKey(_ + _)
        .map({ case ((ipDst, word), count) => SpotLDACInput(ipDst, word, count) })
    


    val SpotLDACOutput(ipToTopicMix, wordToPerTopicProb) = SpotLDACWrapper.runLDA(ipDstWordCounts,
      config.modelFile,
      config.topicDocumentFile,
      config.topicWordFile,
      config.mpiPreparationCmd,
      config.mpiCmd,
      config.mpiProcessCount,
      config.topicCount,
      config.localPath,
      config.ldaPath,
      config.localUser,
      config.analysis,
      config.nodes,
      config.ldaPRGSeed)


       // n@@@@@@@@@@@@@@@ INSERTED EXTRA CODE BELOW

    val wordToPerTopicProbList = wordToPerTopicProb.toList

    def insertStringIntoArray (stringToInsert: String, rawArray: Array[Double]) = {
      val rawArrayLength: Int = rawArray.length
      var arrayWithString = Array[(Double,String)]()
      for(i <- 0 to rawArrayLength-1)
        // Rounding Double values to nearest thousandth
        arrayWithString = arrayWithString.++(Array(((math floor rawArray.apply(i)*1000)/1000, stringToInsert)))
      arrayWithString
    }


    // Attaches the string associated to a given array into each entry of the array (in order that sorting can be performed without loosing the associated string))
    def stringIntoAllArrays (rawList : List[(String, Array[Double])]): Array[Array[(Double, String)]] = {
      var arrayWithStringsInserted = Array[Array[(Double, String)]]()
      val rawListLength = rawList.length
      for(i <- 0 to rawListLength-1)
        arrayWithStringsInserted = arrayWithStringsInserted.++(Array(insertStringIntoArray(rawList.apply(i)._1, rawList.apply(i)._2)))
      arrayWithStringsInserted
    }



    val stringInAllArrays = stringIntoAllArrays(wordToPerTopicProbList)

    // Here hard coded the number of topics
    val numberOfTopics = 20


    // Sort each topic word list (column) so that highest weighted words come to the top.
    def sortTopicWords (wordWithProbsUnsorted : Array[Array[(Double, String)]], numberOfTopics: Int) : Array[Array[(Double, String)]] = {
      val probWithWordsUnsorted = wordWithProbsUnsorted.transpose
      var sortedTopicWords = Array[Array[(Double, String)]]()
      val newEntriesUnsorted = for {i <- 0 to numberOfTopics - 1} yield Array(probWithWordsUnsorted.apply(i))
      val list = for {entry <- newEntriesUnsorted} yield entry.transpose.sortWith((x, y) => y.apply(0)._1 < x.apply(0)._1)
      val intermediateList = for {entry <- list} yield entry.take(10).transpose
      for (entry <- intermediateList)
        sortedTopicWords = sortedTopicWords.++(entry)
      sortedTopicWords

    }

  
    val sortedArrayOfTopicWords = sortTopicWords(stringInAllArrays, numberOfTopics)
    
    // Here printiing to screen
    println("What Follows is the Top 10 Words for each Topic from DNS Analysis, Topics in Rows:") 
    for(i<-0 to 19)
      println(sortedArrayOfTopicWords.apply(i).mkString(""))

    // Here printing the output to an hdfs file path in a compresses format. The appropriate file path needs to be created in the hdfs file system.
    sparkContext.parallelize(sortedArrayOfTopicWords).saveAsTextFile("/user/duxbury/dns/test/topic_profiles/20160520.txt")



    // @@@@@@@@@@@@@@@@@@@@@@@@@@ INSERTED EXTRA CODE ABOVE

    new DNSSuspiciousConnectsModel(topicCount,
      ipToTopicMix,
      wordToPerTopicProb,
      timeCuts,
      frameLengthCuts,
      subdomainLengthCuts,
      numberPeriodsCuts,
      entropyCuts)
  }

  /**
    * Add  domain statistics fields to a data frame.
    *
    * @param sparkContext   Spark context.
    * @param sqlContext     Spark SQL context.
    * @param countryCodesBC Broadcast of the country codes set.
    * @param topDomainsBC   Broadcast of the most-popular domains set.
    * @param inDF           Incoming dataframe. Schema is expected to provide the field [[QueryName]]
    * @return A new dataframe with the new columns added. The new columns have the schema [[DomainStatsSchema]]
    */

  def createDomainStatsDF(sparkContext: SparkContext,
                          sqlContext: SQLContext,
                          countryCodesBC: Broadcast[Set[String]],
                          topDomainsBC: Broadcast[Set[String]],
                          inDF: DataFrame): DataFrame = {
    val queryNameIndex = inDF.schema.fieldNames.indexOf(QueryName)

    val domainStatsRDD: RDD[Row] = inDF.rdd.map(row =>
      Row.fromTuple(createTempFields(countryCodesBC, topDomainsBC, row.getString(queryNameIndex))))

    sqlContext.createDataFrame(domainStatsRDD, DomainStatsSchema)
  }


  case class TempFields(topDomainClass: Int, subdomainLength: Integer, subdomainEntropy: Double, numPeriods: Integer)

  /**
    *
    * @param countryCodesBC Broadcast of the country codes set.
    * @param topDomainsBC   Broadcast of the most-popular domains set.
    * @param url            URL string to anlayze for domain and subdomain information.
    * @return [[TempFields]]
    */
  def createTempFields(countryCodesBC: Broadcast[Set[String]],
                       topDomainsBC: Broadcast[Set[String]],
                       url: String): TempFields = {

    val DomainInfo(_, topDomainClass, subdomain, subdomainLength, subdomainEntropy, numPeriods) =
      DomainProcessor.extractDomainInfo(url, topDomainsBC)


    TempFields(topDomainClass = topDomainClass,
      subdomainLength = subdomainLength,
      subdomainEntropy = subdomainEntropy,
      numPeriods = numPeriods)
  }
}
