from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
#from sqlalchemy import create_engine
 
Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

 
class Domain(Base):
    __tablename__ = 'domain'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    description = Column(String())
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'description'  : self.description
    }
 

class Author(Base):
  __tablename__ = 'author'

  id = Column(Integer, primary_key=True)
  name = Column(String(250), nullable=False)
  about = Column(String())
  user_id = Column(Integer, ForeignKey('user.id'))
  user = relationship(User)

  @property
  def serialize(self):
      return{
        'name': self.name
      }

class ReadingItem(Base):
    __tablename__ = 'reading_item'


    name =Column(String(80), nullable = False)
    id = Column(Integer, primary_key = True)
    synopsis = Column(String())
    domain_id = Column(Integer,ForeignKey('domain.id'))
    author_id = Column(Integer, ForeignKey('author.id'))
    user_id = Column(Integer, ForeignKey('user.id'))
    domain = relationship(Domain)
    author = relationship(Author)
    user = relationship(User)


    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'author'       : self.author.name,
           'id'           : self.id,
           'synopsis'     : self.synopsis
       }
