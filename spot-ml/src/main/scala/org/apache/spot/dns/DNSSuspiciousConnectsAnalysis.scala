package org.apache.spot.dns

import org.apache.spark.SparkContext
import org.apache.spark.sql.{Row, SQLContext, SaveMode, DataFrame}
import org.apache.spark.sql.hive.HiveContext
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types._
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.dns.DNSSchema._
import org.apache.spot.dns.model.DNSSuspiciousConnectsModel
import org.apache.log4j.Logger

import org.apache.spot.dns.model.DNSSuspiciousConnectsModel.ModelSchema

/**
  * The suspicious connections analysis of DNS log data develops a probabilistic model the DNS queries
  * made by each client IP and flags
  */

object DNSSuspiciousConnectsAnalysis {

  val inSchema = StructType(List(TimestampField, UnixTimestampField, FrameLengthField, ClientIPField,
      QueryNameField, QueryClassField, QueryTypeField, QueryResponseCodeField))

  val inColumns = inSchema.fieldNames.map(col)


  assert(ModelSchema.fields.forall(inSchema.fields.contains(_)))
 /**
  val OutSchema = StructType(
    List(TimestampField,
      UnixTimestampField,
      FrameLengthField,
      ClientIPField,
      QueryNameField,
      QueryClassField,
      QueryTypeField,
      QueryResponseCodeField,
      ScoreField))

  val OutColumns = OutSchema.fieldNames.map(col)

   */
  /**
    * Run suspicious connections analysis on DNS log data.
    *
    * @param config Object encapsulating runtime parameters and CLI options.
    * @param sparkContext
    * @param sqlContext
    * @param logger
    */
  def run(config: SuspiciousConnectsConfig, sparkContext: SparkContext, sqlContext: SQLContext, logger: Logger) = {

    val hiveContext = new HiveContext(sparkContext)

    logger.info("Starting DNS suspicious connects analysis.")
    logger.info("Loading data")

    val rawDataDF = sqlContext.read.parquet(config.inputPath)
      .filter(Timestamp + " is not null and " + UnixTimestamp + " is not null")
      .select(inColumns:_*)

    logger.info("Training the model")

    val model =
      DNSSuspiciousConnectsModel.trainNewModel(sparkContext, sqlContext, logger, config, rawDataDF, config.topicCount)

    logger.info("Scoring")
    val scoredDF = model.score(sparkContext, sqlContext, rawDataDF)
    // ...............................below is Gustavos code


    val scoredWithIndexMapRDD = scoredDF.orderBy(Score).rdd.zipWithIndex()
    val scoredWithIndexRDD = scoredWithIndexMapRDD.map({case (row: Row, index: Long) => Row.fromSeq(row.toSeq ++ Array(index.toString))})

    val newDFStruct = new StructType(
      Array(
        StructField("timeStamp", StringType),
        StructField("unixTimeStamp", StringType),
        StructField("frameLength",StringType),
        StructField("clientIP",StringType),
        StructField("queryName",StringType),
        StructField("queryClass",IntegerType),
        StructField("queryType",StringType),
        StructField("queryResponseCode",IntegerType),
        StructField("score",DoubleType),
        StructField("index",StringType)))

    val indexDF = hiveContext.createDataFrame(scoredWithIndexRDD, newDFStruct)

    logger.info(indexDF.count.toString)
    logger.info("persisting data with indexes")
    indexDF.write.mode(SaveMode.Overwrite).saveAsTable("`brandon_dns_spark`")

    logger.info("Proxy suspcicious connects completed")
    logger.info("Saving results to : brandon_dns_spark")

    // ........................................what was is below, above is Gustavos code

    /**

    val filteredDF = scoredDF.filter(Score + " <= " + config.threshold)
    val mostSusipiciousDF: DataFrame = filteredDF.orderBy(Score).limit(config.maxResults)

    val outputDF = mostSusipiciousDF.select(OutColumns:_*).sort(Score)

    logger.info("DNS  suspcicious connects analysis completed.")
    logger.info("Saving results to : " + config.hdfsScoredConnect)
    outputDF.map(_.mkString(config.outputDelimiter)).saveAsTextFile(config.hdfsScoredConnect)
      */
  }
}