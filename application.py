#!/usr/bin/env python2
# Copyright (c) 2019-01 George N. All rights reserved.

import random
import string
import json
import pprint

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    jsonify,
    url_for,
    flash,
    make_response,
    session as login_session
)

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import requests
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Domain, Author, ReadingItem
from sqlalchemy.orm.exc import NoResultFound


# Create server app object
app = Flask(__name__)


CLIENT_ID = json.loads(
    open('g_client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Readings App"


# Connect to Database and create database session
engine = create_engine(
    'sqlite:///readings.db',
    connect_args={'check_same_thread': False}
    )
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token
@app.route('/login')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    return render_template('login.html', STATE=state)


# Facebook login functionality
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, access_token)  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value for the server access token then we
        split it on colons to pull out the actual token value and replace the
        remaining quotes with nothing so that it can be used directly in the
        graph api calls.
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 300px;'
               'height: 300px;'
               'border-radius: 150px;'
               '-webkit-border-radius: 150px;'
               '-moz-border-radius: 150px;"> ')

    flash("Now logged in as %s" % login_session['username'])
    return output


# Facebook logout functionality
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' \
        % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# Connect to google auth server to exchage code for token and then request
# the resource from the resource server
@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('g_client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200
            )
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check if user exists in the DB and if not, add her
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += (' " style = "width: 300px;'
               'height: 300px;'
               'border-radius: 150px;'
               '-webkit-border-radius: 150px;'
               '-moz-border-radius: 150px;"> ')
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


# User Helper Functions
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except NoResultFound:
        return None


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')

    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token={%s}' % access_token  # noqa
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]

    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'


# Disconnect based on provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showDomains'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showDomains'))


# Create routes and functions
@app.route('/')
@app.route('/domains/')
def showDomains():
    """Render a page with all the reading domains

    Returns:
        on GET: a page with all the reading domains and associated
        links
    """
    domains = session.query(Domain).order_by(asc(Domain.name))
    return render_template('showDomains.html', domains=domains)


@app.route('/domains/JSON')
def domainsJSON():
    """API endpoint for domains data

    Returns:
        on GET: a JSON object with the name, description and DB id
        of each domain
    """
    domains = session.query(Domain).all()
    return jsonify(domains=[domain.serialize for domain in domains])


@app.route('/authors/')
def showAuthors():
    """Render a page with all distinct authors

    Returns:
        on GET: A page with each unique author present in the DB
    """
    try:
        authors = session.query(Author).filter(Author.name != '').all()
    except NoResultFound:
        return 'The authors database is emtpy.'
    return render_template('showAuthors.html', authors=authors)


@app.route('/authors/JSON')
def authorsJSON():
    """API endpoint for authors data

    Returns:
        on GET: a JSON object with the name, description of each author
    """
    try:
        authors = session.query(Author).filter(Author.name != '').all()
    except NoResultFound:
        return 'The authors database is emtpy.'
    return jsonify(authors=[author.serialize for author in authors])


@app.route('/domains/<int:domain_id>/readings')
def showReadings(domain_id):
    """Render a page with all the readings pertaining to a domain

    Args:
        domain ID, which is generated by once the domain link is clicked

    Returns:
        on GET: a page with all the readings pertaining to a domain
    """
    domain = session.query(Domain).filter_by(id=domain_id).one()
    readings = session.query(
        ReadingItem, Author).filter(
        ReadingItem.author_id ==
        Author.id).filter(ReadingItem.domain_id == domain.id).all()
    return render_template(
        'showReadings.html',
        domain=domain,
        readings=readings
        )


@app.route('/domains/<int:domain_id>/readings/JSON')
def readingItemsJSON(domain_id):
    """API endpoint for readings data

    Args:
        Domain ID

    Returns:
        on GET: a JSON object with the title, author and synopsis and DB id
        of each reading under the domain
    """
    readings = session.query(ReadingItem).filter_by(domain_id=domain_id).all()
    return jsonify(readings=[reading.serialize for reading in readings])


@app.route('/domains/new', methods=['GET', 'POST'])
def addDomain():
    """Add new domain to DB and re-render the page with all domains

    Returns:
        checks if the user is logged in. If not, redirects to the
        login page.
        on POST: adds the new domain to DB and redirects to the page which
        shows all the domains
        on GET: renders page to add a domain
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        domain = Domain(name=request.form['name'],
                        description=request.form['description'],
                        user_id=login_session['user_id'])
        session.add(domain)
        session.commit()
        return redirect(url_for('showDomains'))
    else:
        return render_template('addDomain.html')


@app.route('/domains/<int:domain_id>/edit', methods=['GET', 'POST'])
def editDomain(domain_id):
    """Edit existing domain

    Args:
        domain ID

    Returns:
        checks if the user is logged in; if not, redirects to login page
        then checks if the user happens to be the one who created the
        domain; if not, shows a denial message
        on POST: updates the database with the relevant edits and redirects
        to all domains page
        on GET: renders the edit domain page
    """
    if 'username' not in login_session:
        return redirect('/login')
    domain = session.query(Domain).filter_by(id=domain_id).one()
    if domain.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                " {alert('You are not authorized to edit this domain."
                " Please create your own domain in order to edit.');}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name'] and request.form['name'] != domain.name:
            domain.name = request.form['name']
            session.commit()
            flash('Domain name successfully edited.')
        if request.form['description'] and request.form['description'] \
                != domain.description:
            domain.description = request.form['description']
            session.commit()
            flash('Domain description successfully edited.')
        return redirect(url_for('showDomains'))
    else:
        return render_template('editDomain.html', domain=domain)


@app.route('/domains/<int:domain_id>/delete', methods=['GET', 'POST'])
def deleteDomain(domain_id):
    """Delete domain

    Args:
        domain ID

    Returns:
        checks if the user is logged in; if not, redirects to login page
        then checks if the user happens to be the one who created the
        domain; if not, shows a denial message
        on POST: deletes the domain from the database and redirects
        to all domains page
        on GET: renders the delete domain page
    """
    if 'username' not in login_session:
        return redirect('/login')
    domain = session.query(Domain).filter_by(id=domain_id).one()
    if domain.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                " {alert('You are not authorized to delete this domain"
                " as you did not create it.');}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['action'] == 'delete':
            try:
                session.query(ReadingItem).filter_by(domain_id=domain_id).one()
                return ("<script>function myFunction()"
                        " {alert('You cannot to delete this domain"
                        " as it has readings listed under it.');}"
                        "</script><body onload='myFunction()''>")
            except NoResultFound:
                session.delete(domain)
                session.commit()
        return redirect(url_for('showDomains'))
    else:
        return render_template('deleteDomain.html', domain=domain)


@app.route('/domains/<int:domain_id>/readings/new', methods=['GET', 'POST'])
def addReading(domain_id):
    """Add new reading to DB and re-render all the readings under the domain

    Args:
        domain ID

    Returns:
        checks if the user is logged in. If not, redirects to the
        login page.
        on POST: add the reading the the DB and redirects to the page
        which shows all the readings under the domain
        on GET: renders the page to add a reading
    """
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        try:
            author = session.query(Author).\
                filter_by(name=request.form['author']).one()
        except NoResultFound:
            author = Author(name=request.form['author'],
                            user_id=login_session['user_id'])
            session.add(author)
            session.commit()
        reading = ReadingItem(name=request.form['title'],
                              synopsis=request.form['synopsis'],
                              author_id=author.id,
                              domain_id=domain_id,
                              user_id=login_session['user_id'])
        session.add(reading)
        session.commit()
        return redirect(url_for('showReadings', domain_id=domain_id))
    else:
        return render_template('addReading.html')


@app.route('/domains/<int:domain_id>/readings/<reading_id>/edit',
           methods=['GET', 'POST'])
def editReading(domain_id, reading_id):
    """Edit existing reading

    Args:
        domain ID
        reading ID

    Returns:
        checks if the user is logged in; if not, redirects to login page
        then checks if the user happens to be the one who created the
        reading; if not, shows a denial message
        on POST: updates the database with the relevant edits and redirects
        to all readings page under the domains
        on GET: renders the edit reading page
    """
    if 'username' not in login_session:
        return redirect('/login')
    reading = session.query(ReadingItem).filter_by(id=reading_id).one()
    author = session.query(Author).filter_by(id=reading.author_id).one()
    if reading.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                " {alert('You are not authorized to edit this reading."
                " Please create your own reading in order to edit.');}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['name'] and request.form['name'] != reading.name:
            reading.name = request.form['name']
        if (request.form['synopsis'] and
           request.form['synopsis'] != reading.synopsis):
            reading.synopsis = request.form['synopsis']
        if request.form['author'] and request.form['author'] != author.name:
            author.name = request.form['author']
        session.commit()
        flash('Reading successfully edited')
        return redirect(url_for('showReadings', domain_id=domain_id))
    else:
        return render_template(
            'editReading.html',
            reading=reading,
            author=author
            )


@app.route('/domains/<int:domain_id>/readings/<reading_id>/delete',
           methods=['GET', 'POST'])
def deleteReading(domain_id, reading_id):
    """Delete reading

    Args:
        domain ID
        reading ID

    Returns:
        checks if the user is logged in; if not, redirects to login page
        then checks if the user happens to be the one who created the
        reading; if not, shows a denial message
        on POST: deletes the reading from the database and redirects
        to all readings page under the domains
        on GET: renders the delete reading page
    """
    if 'username' not in login_session:
        return redirect('/login')
    reading = session.query(ReadingItem).filter_by(id=reading_id).one()
    domain = session.query(Domain).filter_by(id=domain_id).one()
    if reading.user_id != login_session['user_id']:
        return ("<script>function myFunction()"
                " {alert('You are not authorized to edit this reading."
                " Please create your own reading in order to edit.');}"
                "</script><body onload='myFunction()''>")
    if request.method == 'POST':
        if request.form['action'] == 'delete':
            session.delete(reading)
            session.commit()
            flash('Successfully deleted {0.name} from {1.name} domain.'
                  .format(reading, domain))
        return redirect(url_for('showReadings', domain_id=domain_id))
    else:
        return render_template(
            'deleteReading.html',
            reading=reading,
            domain=domain
            )


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
