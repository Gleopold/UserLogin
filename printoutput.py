import os
from sqlalchemy import create_engine

dbname = 'database.db'

engine = create_engine('sqlite:///' + dbname)
result = engine.execute('SELECT * FROM user')

for row in result:
    print(row)

result.close()