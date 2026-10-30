import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main

class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        main.DB = Path(self.tmp.name) / "test.db"
        main.init_db()
        with main.connect() as c:
            c.execute("INSERT INTO users(id,name,email,password_hash) VALUES('u1','Test','t@example.com','x')")
            c.execute("INSERT INTO policies(user_id,per_tx,daily,monthly,currency,mode,merchants,approval_threshold,approval_new) VALUES('u1',50,100,1000,'USD','allowlist','[\"office-grove\"]',35,0)")
        self.c=main.connect()
        self.policy=self.c.execute("SELECT * FROM policies WHERE user_id='u1'").fetchone()

    def tearDown(self):
        self.c.close(); self.tmp.cleanup()

    def test_permitted_purchase(self):
        self.assertEqual(main.evaluate(self.c,'u1',main.CATALOG[0],self.policy)[0],'ALLOWED')

    def test_per_transaction_limit(self):
        self.assertEqual(main.evaluate(self.c,'u1',main.CATALOG[1],self.policy)[0],'BLOCKED_BUDGET')

    def test_restricted_merchant(self):
        self.assertEqual(main.evaluate(self.c,'u1',main.CATALOG[2],self.policy)[0],'BLOCKED_MERCHANT')

    def test_approval_threshold(self):
        self.c.execute("UPDATE policies SET approval_threshold=10 WHERE user_id='u1'")
        p=self.c.execute("SELECT * FROM policies WHERE user_id='u1'").fetchone()
        self.assertEqual(main.evaluate(self.c,'u1',main.CATALOG[0],p)[0],'PENDING_APPROVAL')

    def test_daily_budget_reservation(self):
        now=main.time.time()
        self.c.execute("INSERT INTO proposals VALUES('p','u1','k','paper-01','agent','office-grove','Office Grove','paper',95,'USD','READY_FOR_PAYMENT','ALLOWED','ok','x',?)",(now,))
        self.assertEqual(main.evaluate(self.c,'u1',main.CATALOG[0],self.policy)[0],'BLOCKED_BUDGET')

    def test_missing_policy_blocks(self):
        self.assertEqual(main.evaluate(self.c,'missing',main.CATALOG[0],None)[0],'BLOCKED_POLICY')

if __name__=='__main__': unittest.main()
