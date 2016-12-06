package org.apache.spot.proxy

import org.apache.log4j.Logger
import org.apache.spark.SparkContext
import org.apache.spark.sql.SQLContext
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.proxy.ProxySchema._
import org.apache.spot.utilities.DataFrameUtils

/**
  * Run suspicious connections analysis on proxy data.
  */
object ProxySuspiciousConnectsAnalysis {

  /**
    * Run suspicious connections analysis on proxy data.
    *
    * @param config       SuspicionConnectsConfig object, contains runtime parameters from CLI.
    * @param sparkContext Apache Spark context.
    * @param sqlContext   Spark SQL context.
    * @param logger       Logs execution progress, information and errors for user.
    */
  def run(config: SuspiciousConnectsConfig, sparkContext: SparkContext, sqlContext: SQLContext, logger: Logger) = {

    logger.info("Starting proxy suspicious connects analysis.")

    logger.info("Loading data from: " + config.inputPath)

    val rawDataDF = sqlContext.read.parquet(config.inputPath)
      .filter(s"$Date IS NOT NULL AND $Time  IS NOT NULL AND $ClientIP IS NOT NULL AND " +
        s"$Host IS NOT NULL AND $FullURI IS NOT NULL")
      .select(Date, Time, ClientIP, Host, ReqMethod, UserAgent, ResponseContentType, Duration, UserName,
        WebCat, Referer, RespCode, URIPort, URIPath, URIQuery, ServerIP, SCBytes, CSBytes, FullURI)
      .na.fill("-", Seq(UserAgent))
      .na.fill("-", Seq(ResponseContentType))

    logger.info("Training the model")
    val model =
      ProxySuspiciousConnectsModel.trainNewModel(sparkContext, sqlContext, logger, config, rawDataDF)

    logger.info("Scoring")
    val scoredDF = model.score(sparkContext, rawDataDF)

    // take the maxResults least probable events of probability below the threshold and sort

    val filteredDF = scoredDF
      .filter(Score +  " <= " + config.threshold + " AND " + Score + " > -1 ")
    val topRows = DataFrameUtils.dfTakeOrdered(filteredDF, "score", config.maxResults)
    val scoreIndex = scoredDF.schema.fieldNames.indexOf("score")
    val outputRDD = sparkContext.parallelize(topRows).sortBy(row => row.getDouble(scoreIndex))

    logger.info("Persisting data")
    outputRDD.map(_.mkString(config.outputDelimiter)).saveAsTextFile(config.hdfsScoredConnect)

    logger.info("Proxy suspcicious connects completed")

    val invalidRecords = sqlContext.read.parquet(config.inputPath)
      .filter(s"$Date IS NULL OR $Time  IS NULL OR $ClientIP IS NULL OR " +
        s"$Host IS NULL OR $FullURI IS NULL")
    if(invalidRecords.count >0){

      val invalidRecordsFile = config.hdfsScoredConnect + "/invalid_records"
      logger.warn("Saving invalid records to " + invalidRecordsFile)

      invalidRecords.write.mode("overwrite").parquet(invalidRecordsFile)

      logger.warn("Total records discarded due to NULL values in key fields: " + invalidRecords.count +
        " . Please go to " + invalidRecordsFile +" for more details.")
    }

    val corruptedDF = scoredDF.filter(Score + " = -1")
    if(corruptedDF.count > 0){

      val corruptRecordsFile = config.hdfsScoredConnect + "/corrupt_records"

      logger.warn("Saving corrupt records to " + corruptRecordsFile)

      corruptedDF.write.mode("overwrite").parquet(corruptRecordsFile)

      logger.warn("Total records discarded due to invalid values in key fields: " + corruptedDF.count +
        "Please go to " + corruptRecordsFile + " for more details.")
    }
  }
}