from app.database import engine, Base, SessionLocal
from app.seed_data import seed_enterprise_demonstration
from app.models.asset import Application
from app.models.vulnerability import Vulnerability
from app.models.organization import User

def run_test():
    print("1. Creating database tables synchronously...")
    Base.metadata.create_all(bind=engine)
    print("2. Seeding enterprise demonstration data synchronously...")
    with SessionLocal() as session:
        seed_enterprise_demonstration(session)
        apps = session.query(Application).all()
        vulns = session.query(Vulnerability).all()
        users = session.query(User).all()
        print(f"SUCCESS: Seeded {len(apps)} Applications, {len(vulns)} Vulnerabilities, {len(users)} Users.")

if __name__ == "__main__":
    run_test()
