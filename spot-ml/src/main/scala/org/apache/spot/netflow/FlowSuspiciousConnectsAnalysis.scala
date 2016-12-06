package org.apache.spot.netflow

import org.apache.log4j.Logger
import org.apache.spark.{Accumulable, SparkContext}
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types.StructType
import org.apache.spark.sql.{DataFrame, SQLContext}
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.netflow.FlowSchema._
import org.apache.spot.netflow.model.FlowSuspiciousConnectsModel

import scala.collection.mutable


/**
  * The suspicious connections analysis of netflow records develops a probabilistic model the traffic about each
  * IP and flags transactions with an exceptionally low probability in the model as anomalous.
  */

object FlowSuspiciousConnectsAnalysis {

  def run(config: SuspiciousConnectsConfig, sparkContext: SparkContext, sqlContext: SQLContext, logger: Logger)
         (implicit outputDelimiter: String) = {

    logger.info("Loading data")

    val rawDataDF = sqlContext.read.parquet(config.inputPath)
      .filter(s"$Hour BETWEEN 0 AND 23 AND $Minute BETWEEN 0 AND 59 AND $Second BETWEEN 0 AND 59 AND " +
        s"$TimeReceived IS NOT NULL AND $SourceIP IS NOT NULL AND $DestinationIP IS NOT NULL AND " +
        s"$SourcePort IS NOT NULL AND $DestinationPort IS NOT NULL AND $Ibyt IS NOT NULL AND $Ipkt IS NOT NULL")
      .select(inColumns: _*)

    logger.info("Training the model")

    val model =
      FlowSuspiciousConnectsModel.trainNewModel(sparkContext, sqlContext, logger, config, rawDataDF, config.topicCount)

    logger.info("Scoring")
    val scoredDF = model.score(sparkContext, sqlContext, rawDataDF)

    val filteredDF = scoredDF
      .filter(Score + " <= " + config.threshold + " AND " + Score + " > -1 ")

    val mostSusipiciousDF: DataFrame = filteredDF.orderBy(Score).limit(config.maxResults)

    val outputDF = mostSusipiciousDF.select(OutColumns: _*)

    logger.info("Netflow  suspicious connects analysis completed.")
    logger.info("Saving results to : " + config.hdfsScoredConnect)
    outputDF.map(_.mkString(config.outputDelimiter)).saveAsTextFile(config.hdfsScoredConnect)

    val invalidRecords = sqlContext.read.parquet(config.inputPath).filter(s"$Hour BETWEEN 0 AND 23 AND $Minute " +
      s"BETWEEN 0 AND 59 AND $Second BETWEEN 0 AND 59 AND (" +
      s"$TimeReceived IS NULL OR $SourceIP IS NULL OR $DestinationIP IS NULL OR " +
      s"$SourcePort IS NULL OR $DestinationPort IS NULL OR $Ibyt IS NULL OR $Ipkt IS NULL)")
    if (invalidRecords.count > 0){

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

  val inSchema = StructType(List(TimeReceivedField,
    YearField,
    MonthField,
    DayField,
    HourField,
    MinuteField,
    SecondField,
    DurationField,
    SourceIPField,
    DestinationIPField,
    SourcePortField,
    DestinationPortField,
    ProtocolField,
    IpktField,
    IbytField,
    OpktField,
    ObytField))

  val inColumns = inSchema.fieldNames.map(col)

  val OutSchema = StructType(
    List(TimeReceivedField,
      YearField,
      MonthField,
      DayField,
      HourField,
      MinuteField,
      SecondField,
      DurationField,
      SourceIPField,
      DestinationIPField,
      SourcePortField,
      DestinationPortField,
      ProtocolField,
      IpktField,
      IbytField,
      OpktField,
      ObytField,
      ScoreField))

  val OutColumns = OutSchema.fieldNames.map(col)
}