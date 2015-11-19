import org.springframework.dao._
import org.springframework.jdbc.core._
import org.springframework.jdbc.core.simple._
import org.springframework.jdbc.datasource._
import java.sql.ResultSet

trait JdbcHelpers {
  type ExtractorFunction[T] = ResultSet => T
  type RowMappingFunction[T] = (ResultSet, Integer) => T

  def extract[T](callback: ExtractorFunction[T]): ResultSetExtractor[Option[T]] = new ResultSetExtractor[Option[T]]() {
    def extractData(rs: ResultSet): Option[T] = if (rs.next) Option(callback(rs)) else None
  }

  def mappingRows[T](callback: RowMappingFunction[T]): RowMapper[T] = new RowMapper[T]() {
    def mapRow(rs: ResultSet, rn: Int): T = callback(rs, rn)
  }

  def get[T](db: JdbcTemplate)(query: String, args: Object*)(callback: ExtractorFunction[T]): Option[T] = db.query(query, args.toArray, extract(callback))

  def query[T](db: JdbcTemplate)(query: String, args: Object*)(callback: RowMappingFunction[T]): java.util.List[T] = db.query(query, args.toArray, mappingRows(callback))

  def queryForObject[T](db: JdbcTemplate)(query: String, args: Array[Object], argTypes: Array[Int])(callback: RowMappingFunction[T]): Option[T] = Try {
    Some(db.queryForObject(query, args, argTypes, mappingRows(callback)))
  } recover {
    case e: EmptyResultDataAccessException => None
  } get

  def update(db: JdbcTemplate)(query: String)(args: Object*): Int = db.update(query, new ArgumentPreparedStatementSetter(args.toArray))

}
