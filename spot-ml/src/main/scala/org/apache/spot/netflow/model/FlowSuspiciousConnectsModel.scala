package org.apache.spot.netflow.model

import org.apache.log4j.Logger
import org.apache.spark.SparkContext
import org.apache.spark.broadcast.Broadcast
import org.apache.spark.rdd.RDD
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types.StructType
import org.apache.spark.sql.{DataFrame, Row, SQLContext, WideUDFs}
import org.apache.spot.SpotLDACWrapper
import org.apache.spot.SpotLDACWrapper.{SpotLDACInput, SpotLDACOutput}
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.netflow.FlowSchema._
import org.apache.spot.netflow.FlowWordCreator
import org.apache.spot.utilities.Quantiles
import WideUDFs.udf

/**
  * A probabilistic model of the netflow traffic observed in a network.
  *
  * The model uses a topic-modelling approach that:
  * 1. Simplifies netflow records into words, one word at the source IP and another (possibly different) at the
  *    destination IP.
  * 2. The netflow words about each IP are treated as collections of thes words.
  * 3. A topic modelling approach is used to infer a collection of "topics" that represent common profiles
  *    of network traffic. These "topics" are probability distributions on words.
  * 4. Each IP has a mix of topics corresponding to its behavior.
  * 5. The probability of a word appearing in the traffic about an IP is estimated by simplifying its netflow record
  *    into a word, and then combining the word probabilities per topic using the topic mix of the particular IP.
  *
  * Create these models using the  factory in the companion object.
  *
  * @param topicCount Number of topics (profiles of common traffic patterns) used in the topic modelling routine.
  * @param ipToTopicMix Map assigning a distribution on topics to each IP.
  * @param wordToPerTopicProb Map assigning to each word it's per-topic probabilities.
  *                           Ie. Prob [word | t ] for t = 0 to topicCount -1
  * @param timeCuts Quantile cut-offs for binning time-of-day values when forming words from netflow records.
  * @param ibytCuts Quantile cut-offs for binning ibyt values when forming words from netflow records.
  * @param ipktCuts Quantile cut-offs for binning ipkt values when forming words from netflow records.
  */

class FlowSuspiciousConnectsModel(topicCount: Int,
                                  ipToTopicMix: Map[String, Array[Double]],
                                  wordToPerTopicProb: Map[String, Array[Double]],
                                  timeCuts: Array[Double],
                                  ibytCuts: Array[Double],
                                  ipktCuts: Array[Double]) {


  def score(sc: SparkContext, sqlContext: SQLContext, flowRecords: DataFrame): DataFrame = {


    import sqlContext.implicits._
    val ipToTopicMixRDD: RDD[(String, Array[Double])] = sc.parallelize(ipToTopicMix.toSeq)
    val ipToTopicMixDF = ipToTopicMixRDD.map({ case (doc, probabilities) => IpTopicMix(doc, probabilities) }).toDF


    val wordToPerTopicProbBC = sc.broadcast(wordToPerTopicProb)


    /** A left outer join (below) takes rows from the left DF for which the join expression is not
      * satisfied (for any entry in the right DF), and fills in 'null' values (for the additional columns).
      */
    val dataWithSrcTopicMix = {
      val recordsWithSrcIPTopicMixes = flowRecords.join(ipToTopicMixDF,
        flowRecords(SourceIP) === ipToTopicMixDF("ip"), "left_outer")
      val schemaWithSrcTopicMix = flowRecords.schema.fieldNames :+ "topicMix"
      val dataWithSrcIpProb: DataFrame = recordsWithSrcIPTopicMixes.selectExpr(schemaWithSrcTopicMix: _*)
        .withColumnRenamed("topicMix", SrcIpTopicMix)

      val recordsWithIPTopicMixes = dataWithSrcIpProb.join(ipToTopicMixDF,
        dataWithSrcIpProb(DestinationIP) === ipToTopicMixDF("ip"), "left_outer")
      val schema = dataWithSrcIpProb.schema.fieldNames :+  "topicMix"
        recordsWithIPTopicMixes.selectExpr(schema: _*).withColumnRenamed("topicMix", DstIpTopicMix)
    }





    val scoreFunction =  new FlowScoreFunction(timeCuts,
        ibytCuts,
        ipktCuts,
        topicCount,
        wordToPerTopicProbBC)


    val scoringUDF = udf((hour: Int,
                          minute: Int,
                          second: Int,
                          srcIP: String,
                          dstIP: String,
                          srcPort: Int,
                          dstPort: Int,
                          ipkt: Long,
                          ibyt: Long,
                          srcIpTopicMix: Seq[Double],
                          dstIpTopicMix: Seq[Double]) =>
      scoreFunction.score(hour,
        minute,
        second,
        srcIP,
        dstIP,
        srcPort,
        dstPort,
        ipkt,
        ibyt,
        srcIpTopicMix,
        dstIpTopicMix))


    dataWithSrcTopicMix.withColumn(Score,
      scoringUDF(FlowSuspiciousConnectsModel.ModelColumns :+ col(SrcIpTopicMix) :+ col(DstIpTopicMix): _*))

  }




}
case class IpTopicMix(ip: String, topicMix
: Array[Double]) extends Serializable

/**
  * Contains dataframe schema information as well as the train-from-dataframe routine
  * (which is a kind of factory routine) for [[FlowSuspiciousConnectsModel]] instances.
  *
  */
object FlowSuspiciousConnectsModel {

  val ModelSchema = StructType(List(HourField,
    MinuteField,
    SecondField,
    SourceIPField,
    DestinationIPField,
    SourcePortField,
    DestinationPortField,
    IpktField,
    IbytField))

  val ModelColumns = ModelSchema.fieldNames.toList.map(col)

  def trainNewModel(sparkContext: SparkContext,
                    sqlContext: SQLContext,
                    logger: Logger,
                    config: SuspiciousConnectsConfig,
                    inDF: DataFrame,
                    topicCount: Int): FlowSuspiciousConnectsModel = {

    logger.info("Training netflow suspicious connects model from " + config.inputPath)

    val selectedDF = inDF.select(ModelColumns: _*)


    val totalDataDF = selectedDF.unionAll(FlowFeedback.loadFeedbackDF(sparkContext,
      sqlContext,
      config.scoresFile,
      config.duplicationFactor))



    // create quantile cut-offs

    val timeCuts = Quantiles.computeDeciles(totalDataDF
      .select(Hour, Minute, Second)
      .rdd
      .map({ case Row(hours: Int, minutes: Int, seconds: Int) => 3600 * hours + 60 * minutes + seconds }))

    logger.info(timeCuts.mkString(","))

    logger.info("calculating byte cuts ...")

    val ibytCuts = Quantiles.computeDeciles(totalDataDF
      .select(Ibyt)
      .rdd
      .map({ case Row(ibyt: Long) => ibyt.toDouble }))

    logger.info(ibytCuts.mkString(","))

    logger.info("calculating pkt cuts")

    val ipktCuts = Quantiles.computeQuintiles(totalDataDF
      .select(Ipkt)
      .rdd
      .map({ case Row(ipkt: Long) => ipkt.toDouble }))


    logger.info(ipktCuts.mkString(","))

    // simplify DNS log entries into "words"

    val flowWordCreator = new FlowWordCreator(timeCuts, ibytCuts, ipktCuts)

    val srcWordUDF = flowWordCreator.srcWordUDF
    val dstWordUDF = flowWordCreator.dstWordUDF

    val dataWithWordsDF = totalDataDF.withColumn(SourceWord, flowWordCreator.srcWordUDF(ModelColumns: _*))
      .withColumn(DestinationWord, flowWordCreator.dstWordUDF(ModelColumns: _*))
    // aggregate per-word counts at each IP

    val srcWordCounts = dataWithWordsDF.select(SourceIP, SourceWord)
      .map({ case Row(sourceIp: String, sourceWord: String) => (sourceIp, sourceWord) -> 1 })
      .reduceByKey(_ + _)

    val dstWordCounts = dataWithWordsDF.select(DestinationIP, DestinationWord)
      .map({ case Row(destinationIp: String, destinationWord: String) => (destinationIp, destinationWord) -> 1 })
      .reduceByKey(_ + _)

    val ipWordCounts =
      sparkContext.union(srcWordCounts, dstWordCounts)
        .reduceByKey(_ + _)
        .map({ case ((ip, word), count) => SpotLDACInput(ip, word, count) })


    val SpotLDACOutput(ipToTopicMix, wordToPerTopicProb) = SpotLDACWrapper.runLDA(ipWordCounts,
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
    println("What Follows is the Top 10 Words foreach Topic from Flow Analysis, Topics in Rows:")
    val sortedArrayOfTopicWords = sortTopicWords(stringInAllArrays, numberOfTopics)

    // Here printing output to screen
    for(i<-0 to 19)
      println(sortedArrayOfTopicWords.apply(i).mkString(""))


 // Here printing the output to an hdfs file path in a compresses format. The appropriate file path needs to be created in the hdfs file system.
   sparkContext.parallelize(sortedArrayOfTopicWords).saveAsTextFile("/user/duxbury/flow/test/topic_profiles/20160520.txt")



    // @@@@@@@@@@@@@@@@@@@@@@@@@@ INSERTED EXTRA CODE ABOVE

    new FlowSuspiciousConnectsModel(topicCount,
      ipToTopicMix,
      wordToPerTopicProb,
      timeCuts,
      ibytCuts,
      ipktCuts)
  }

}
