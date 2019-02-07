from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base, Domain, ReadingItem, Author, User

engine = create_engine('sqlite:///readings.db')
# Establish (formalize?) metadata
Base.metadata.create_all(engine)
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create user
User1 = User(name="George Nizharadze", email="georgenizharadze@sky.com")
session.add(User1)
session.commit()

# Add theology domain and related readings
domain1 = Domain(name="Theology", user_id=1)

session.add(domain1)
session.commit()

author1 = Author(name="Davis, Ellen and Hays, Richard", user_id=1)

session.add(author1)
session.commit()

readingItem = ReadingItem(name="The Art of Reading Scripture", 
                            synopsis=("Exploration of the significance and understanding"
                                   "of the Bible in this post-modern world."),
                            user_id=1, domain_id=1, author_id=1)

session.add(readingItem)
session.commit()


author2 = Author(name="Williams, Rowan", user_id=1)

session.add(author2)
session.commit()

readingItem = ReadingItem(name="Being Christian", user_id=1, domain_id=1, author_id=2)

session.add(readingItem)
session.commit()

readingItem = ReadingItem(name="Meeting God in Mark", user_id=1, domain_id=1, author_id=2)

session.add(readingItem)
session.commit()


# Add other domains
domain2 = Domain(name="Philosophy", user_id=1)
session.add(domain2)
session.commit()

domain3 = Domain(name="Politics", user_id=1)
session.add(domain3)
session.commit()

domain4 = Domain(name="Arts", user_id=1)
session.add(domain4)
session.commit()

domain5 = Domain(name="Economics", user_id=1)
session.add(domain5)
session.commit()

print "added reading items!"