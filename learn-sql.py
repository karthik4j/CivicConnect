from sqlalchemy import create_engine,MetaData,Table,Column
engine = create_engine('sqlite:///mydatabase.db',echo=True)


meta = MetaData()
people = Table(
  "people",meta,
)