import org.springframework.transaction.support._
import org.springframework.transaction._
import scala.util._

trait TxHelpers {
  type TxCallback[T] = TransactionStatus => T

  private def transactionCallback[T](callback: TxCallback[T]): TransactionCallback[T] = new TransactionCallback[T]() {
    def doInTransaction(status: TransactionStatus): T = callback(status)
  }

  def withTransaction[T](template: TransactionTemplate)(callback: TxCallback[T]): Try[T] = Try {
    template.execute(transactionCallback(callback))
  }
}
