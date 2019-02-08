# Readings application with database back-end

This project contains a RESTful web application - a catalog of readings within various domains such as art, philosophy, economics, etc. The app has a relational database back end; third party authentication and authorization system (via Google and Facebook); it provides the possibility to perform CRUD operations via HTTP GET and POST methods. 

## Setting up and running the application 

To run this application, you need Python 2.7 and its native sqlite database management system. You also need to install SQLAlchemy and Flask packages. 

You can clone the repository. To start the application on your local machine, go into the repository and run `python application.py`. 

The database has already been populated with a number of initial entries. You can add, edit and delete domains and readings within the limits of your access, after you have logged in. 

If you want to programatically create a completely new database, you can build your code off the 
`populate_database.py` file.  