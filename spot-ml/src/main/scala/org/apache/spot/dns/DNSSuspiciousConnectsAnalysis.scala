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
import org.apache.spot.proxy.ProxySchema.Score
import org.apache.spot.utilities.data.validation.{InvalidDataHandler => dataValidation}

/**
  * The suspicious connections analysis of DNS log data develops a probabilistic model the DNS queries
  * made by each client IP and flags
  */

object DNSSuspiciousConnectsAnalysis {

  /**
    * Run suspicious connections analysis on DNS log data.
    *
    * @param config Object encapsulating runtime parameters and CLI options.
    * @param sparkContext
    * @param sqlContext
    * @param logger
    */
  def run(config: SuspiciousConnectsConfig, sparkContext: SparkContext, sqlContext: SQLContext, logger: Logger) = {

    logger.info("Starting DNS suspicious connects analysis.")
    logger.info("Loading data from: " + config.inputPath)

    val userDomain = config.userDomain
    val hiveContext = new HiveContext(sparkContext)

    val rawDataDF = sqlContext.read.parquet(config.inputPath)
      .filter(InputFilter)
      .select(InSchema:_*)
      .na.fill("unknown", Seq(QueryClass))
      .na.fill(-1, Seq(QueryType))
      .na.fill(-1, Seq(QueryResponseCode))

    logger.info("Training the model")

    val model =
      DNSSuspiciousConnectsModel.trainNewModel(sparkContext, sqlContext, logger, config, rawDataDF, config.topicCount)

    logger.info("Scoring")
    val scoredDF = model.score(sparkContext, sqlContext, rawDataDF, userDomain)


    // ...............................below is Gustavos code

    logger.info("Indexing scored results")

    val scoredWithIndexMapRDD = scoredDF.orderBy(Score).rdd.zipWithIndex()
    val scoredWithIndexRDD = scoredWithIndexMapRDD.map({case (row: Row, index: Long) => Row.fromSeq(row.toSeq ++ Array(index.toString))})

    val newDFStruct = new StructType(
      Array(
        StructField("timeStamp", StringType),
        StructField("unixTimeStamp", LongType),
        StructField("frameLength",IntegerType),
        StructField("clientIP",StringType),
        StructField("queryName",StringType),
        StructField("queryClass",StringType),
        StructField("queryType",IntegerType),
        StructField("queryResponseCode",IntegerType),
        StructField("dnsRecordID", StringType),
        StructField("score",DoubleType),
        StructField("index",StringType)))

    val indexDF = hiveContext.createDataFrame(scoredWithIndexRDD, newDFStruct)
    val attackOnlyIndexDF = indexDF.filter(PositiveAttackFilter)

    logger.info(indexDF.count.toString)
    logger.info("Saving results to : brandon_dns_spark")

    attackOnlyIndexDF.write.mode(SaveMode.Overwrite).saveAsTable("`brandon_dns_spark`")

    // ........................................above is Gustavos code


    val filteredDF = scoredDF.filter(Score + " <= " + config.threshold + " AND " + Score + " > -1")
    val mostSuspiciousDF: DataFrame = filteredDF.orderBy(Score).limit(config.maxResults)

    val outputDF = mostSuspiciousDF.select(OutSchema:_*).sort(Score)

    logger.info("DNS  suspicious connects analysis completed.")
    logger.info("Saving results to : " + config.hdfsScoredConnect)
    outputDF.map(_.mkString(config.outputDelimiter)).saveAsTextFile(config.hdfsScoredConnect)

    val invalidRecords = sqlContext.read.parquet(config.inputPath)
      .filter(InvalidRecordsFilter)
      .select(InSchema:_*)

    dataValidation.showAndSaveInvalidRecords(invalidRecords, config.hdfsScoredConnect, logger)

    val corruptRecords = scoredDF.filter(Score + " = -1")
    dataValidation.showAndSaveCorruptRecords(corruptRecords, config.hdfsScoredConnect, logger)
  }


  val InStructType = StructType(List(TimestampField, UnixTimestampField, FrameLengthField, ClientIPField,
    QueryNameField, QueryClassField, QueryTypeField, QueryResponseCodeField, DNSRecordIDField))

  val InSchema = InStructType.fieldNames.map(col)

  assert(ModelSchema.fields.forall(InStructType.fields.contains(_)))

  val OutSchema = StructType(
    List(TimestampField,
      UnixTimestampField,
      FrameLengthField,
      ClientIPField,
      QueryNameField,
      QueryClassField,
      QueryTypeField,
      QueryResponseCodeField,
      DNSRecordIDField,
      ScoreField)).fieldNames.map(col)

  val InputFilter = s"($Timestamp IS NOT NULL AND $Timestamp <> '' AND $Timestamp <> '-') " +
    s"AND ($UnixTimestamp  IS NOT NULL) " +
    s"AND ($FrameLength IS NOT NULL) " +
    s"AND ($QueryName IS NOT NULL AND $QueryName <> '' AND $QueryName <> '-' AND $QueryName <> '(empty)') " +
    s"AND ($ClientIP IS NOT NULL AND $ClientIP <> '' AND $ClientIP <> '-') " +
    s"AND (($QueryClass IS NOT NULL AND $QueryClass <> '' AND $QueryClass <> '-') " +
    s"OR $QueryType IS NOT NULL " +
    s"OR $QueryResponseCode IS NOT NULL)"

  val InvalidRecordsFilter = s"($Timestamp IS NULL OR $Timestamp = '' OR $Timestamp = '-') " +
    s"OR ($UnixTimestamp  IS NULL) " +
    s"OR ($FrameLength IS NULL) " +
    s"OR ($QueryName IS NULL OR $QueryName = '' OR $QueryName = '-' AND $QueryName = '(empty)') " +
    s"OR ($ClientIP IS NULL OR $ClientIP = '' OR $ClientIP = '-') " +
    s"OR (($QueryClass IS NULL OR $QueryClass = '' OR $QueryClass = '-') " +
    s"AND $QueryType IS NULL " +
    s"AND $QueryResponseCode IS NULL)"

  val PositiveAttackFilter = s"(dnsRecordID = '0x00001775') " +
                             s"OR (dnsRecordID = '0x00001776') " +
                             s"OR (dnsRecordID = '0x00001777') " +
                             s"OR (dnsRecordID = '0x00001778') " +
                             s"OR (dnsRecordID = '0x00001779') " +
                             s"OR (dnsRecordID = '0x0000177a') " +
                             s"OR (dnsRecordID = '0x0000177b') " +
                             s"OR (dnsRecordID = '0x0000177c') " +
                             s"OR (dnsRecordID = '0x0000177d') " +
			     s"OR (dnsRecordID = '0x0000177e') " +
                             s"OR (dnsRecordID = '0x0000177f') " +
                             s"OR (dnsRecordID = '0x00001780') " +
                             s"OR (dnsRecordID = '0x00001781') " +
                             s"OR (dnsRecordID = '0x00001782') " +
                             s"OR (dnsRecordID = '0x00001783') " +
                             s"OR (dnsRecordID = '0x00001784') " +
                             s"OR (dnsRecordID = '0x00001785') " +
                             s"OR (dnsRecordID = '0x00001786') " +
                             s"OR (dnsRecordID = '0x00001787') "
}
