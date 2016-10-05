# Python standard library imports
import argparse
import json
import os
import socket
import sys

from glob import glob
from datetime import datetime

# Third party library imports (installed with pip)
from bottle import (app, get, post, response, request, run,
                    jinja2_view, redirect, static_file)
from beaker.middleware import SessionMiddleware

# Local imports
from alerts import load_alerts, save_danger, save_success
from authentication import (
    requires_authentication, validate_login_form,
    check_password, requires_authorization
)
from message import (
    validate_message_form, load_message, load_sent_messages,
    load_received_messages, send_message
)


@get('/')
@jinja2_view("templates/list_messages.html")
@requires_authentication
@load_alerts
def list_messages():
    """Handler for GET requests to ``/`` path.

    * Lists sent and received messages
    * Requires users to be logged in
    * Loads alerts for display
    * Uses "templates/list_messages.html" as its template

    This handler returns a context dictionary with the following fields:

    * ``sent_messages``: A list of loaded messages (dictionaries)
      in reverse chronological order (from most recent to least
      recent) that have been *sent* by the current user.

    * ``received_messages``: A list of loaded messages (dictionaries)
      in reverse chronological order (from most recent to least
      recent) that have been *received* by the current user.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    dict = {}

    # Get's users name from cookie
    user = request.get_cookie("logged_in_as")
    
    # Get lists of sent and received messages
    sent = load_sent_messages(user)
    received = load_received_messages(user)

    # Put into dicitonary
    dict['sent_messages'] = sent
    dict['received_messages'] = received
    
    return dict


@get('/compose/')
@jinja2_view("templates/compose_message.html")
@requires_authentication
@load_alerts # was missing this.
def show_compose_message_form():
    """Handler for GET requests to ``/compose/`` path.

    * Shows a form that can be used to send a new message.
    * Requires users to be logged in
    * Loads alerts for display
    * Uses "templates/compose_message.html" as its template

    This handler returns a context dictionary with the following
    fields:

    * ``people``: A list of usernames (:class:`str`s). A list of every
      username (from ``passwords.json``) excluding the currently
      logged in user.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    dict = {}
    lst = []

    # Open the passwords file
    with open("passwords.json") as f:
        passwords = json.load(f)
        # iterate through each user
        for user in passwords.keys():
            # add every user's name to list except logged in user
            if user !=  request.get_cookie("logged_in_as"):
                lst.append(user)

    dict['people'] = lst
    return dict


@post('/compose/')
@requires_authentication
def process_compose_message_form():
    """Handler for POST requests to ``/compose/`` path.

    * Processes the message form

        1. Validates the submitted form

            - **If the form is has any errors**, saves the errors as
              danger alerts and redirects the user back to ``/compose/``
            - Otherwise (no errors) proceed to step 2.

        2. Saves message data to a new file on disk

        3. Save a success alert message

        4. Redirects the user to ``/``

    * Requires users to be logged in

    :returns: None. This function only redirects users to other
        pages. It has no template to render.

    """
    # Validate the form, get errors if there are any.
    errors = validate_message_form(request.forms)

    # Save errors and redirect
    if errors:
        save_danger(*errors)
        redirect('/compose/')

    # Otherwise get the necessary info in the dictionary
    dict = {}
    dict['to'] = request.forms['to']
    dict['from'] = request.get_cookie("logged_in_as")
    dict['subject'] = request.forms['subject']
    dict['body'] = request.forms['body']
    dict['time'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Send the message (creates a .json file in messages/)
    send_message(dict)

    save_success("Message sent!")
    redirect("/")


@requires_authorization
@get('/view/<message_id:re:[0-9a-f\-]{36}>/')
@jinja2_view("templates/view_message.html")
@load_alerts
def view_message(message_id):
    """Handler for GET requests to ``/view/<message_id>/`` path.

    * Displays a message
    * Requires a user to be authorized to view the message
    * Requires users to be logged in
    * Loads alerts for display
    * Uses "templates/view_message.html" as its template

    This handler returns a context dictionary with the following fields:

    * ``message``: The message dictionary (loaded with
      :func:`message.load_message`) for the given ``message_id``.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    msg = {}
    msg['message'] = load_message(message_id)
    return msg

@requires_authorization
@get('/delete/<message_id:re:[0-9a-f\-]{36}>/')
@jinja2_view("templates/delete_message.html")
def show_deletion_confirmation_form(message_id):
    """Handler for GET requests to ``/delete/<message_id>/`` path.

    * Shows a form that can be used to delete an existing message
    * Requires a user to be authorized to delete the message
    * Requires users to be logged in
    * Loads alerts for display
    * Uses "templates/delete_message.html" as its template

    This handler returns a context dictionary with the following fields:

    * ``message``: The message dictionary (loaded with
      :func:`message.load_message`) for the given ``message_id``.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    dict = {}
    dict['message'] = load_message(message_id)
    return dict

@requires_authorization
@post('/delete/<message_id:re:[0-9a-f\-]{36}>/')
def delete_message(message_id):
    """Handler for POST requests to ``/delete/<message_id>/`` path.

    * Attempts to remove file with message ID ``message_id``

        - If the file could not be removed (``OSError``), then a danger
          alert is saved.
        - If the file was removed successfully, a success alert is saved.
        - In either case, the user is redirected to ``/``.

    * Requires a user to be authorized to delete the message
    * Requires users to be logged in

    :returns: None. This function only redirects users to other
        pages. It has no template to render.

    """

    dir = os.path.join('messages/', '{}.json'.format(message_id))

    try:
        os.remove(dir)
        save_success("Deleted {}.".format(message_id))
        
    except OSError:
        save_danger("No such message {}".format(message_id))
        
    finally:
        redirect("/")


@get('/shred/')
@jinja2_view("templates/shred_messages.html")
@requires_authentication
@load_alerts # I added this
def show_shred_confirmation_form():
    """Handler for GET requests to ``/shred/`` path.

    * Shows a form that can be used to delete all existing messages.
    * Requires users to be logged in
    * Loads alerts for display
    * Uses "templates/shred_messages.html" as its template

    This handler returns an **empty** context dictionary.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    # This function doesn't need to pass any data to the template.
    # Simply return {}
    return {}


@post('/shred/')
@requires_authentication
def shred_messages():
    """Handler for POST requests to ``/shred/`` path.

    * Attempts to remove all saved message files

        - If any files could not be removed (an exception of some sort),
          then a danger alert is saved.
        - If all files were removed successfully, a success alert is saved.
        - In either case, the user is redirected to ``/``

    * Requires users to be logged in

    :returns: None. This function only redirects users to other
        pages. It has no template to render.

    """
    for file in glob('messages/*.json'):
        try:
            os.remove(file)
        except:
            save_danger("something couldn't be shredded")

    if len(glob('messages/*.json')) == 0:
        save_success("Shreded all messages.")

    redirect("/")


@get('/login/')
@jinja2_view("templates/login.html")
@load_alerts
def show_login_form():
    """Handler for GET requests to ``/login/`` path.

    * Shows a form that can be used to submit login credentials
    * Loads alerts for display
    * Uses "templates/login.html" as its template

    This handler returns an **empty** context dictionary.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    # This function doesn't need to pass any data to the template.
    # Simply return {}
    return {}


@post('/login/')
def process_login_form():
    """Handler for POST requests to ``/login/`` path.

    * Processes the login form

        1. Validates the submitted form

            * If the form is has errors, saves the errors as
              danger alerts and redirects the user back to ``/login/``

        2. Checks that the user's username/password combo is good

            * Usernames are case insensitive

        3. Redirects the user

            - If their credentials were good, set their
              ``logged_in_as`` cookie to their username, save a
              success alert, and redirect them to ``/``
            - If their credentials were bad, save a danger alert, and
              redirect them to ``/login/``

    :returns: None. This function only redirects users to other
        pages. It has no template to render.

    """
    errors = validate_login_form(request.forms)
    if errors:
        save_danger(*errors)
        redirect('/login/')

    username = request.forms['username'].lower()
    password = request.forms['password']

    # TODO some kind of actual authentication
    if check_password(username, password):
        response.set_cookie("logged_in_as", username, path='/')
        save_success("Successfully logged in as {}.".format(username))
        redirect("/")
    else:
        save_danger("Incorrect username/password information.")
        redirect("/login/")


@get('/logout/')
@jinja2_view("templates/logged_out.html")
@load_alerts
def logout():
    """Handler for GET requests to ``/logout/`` path.

    * Logs a user out by setting their "logged_in_as" cookie to ""
    * Loads alerts for display
    * Uses "templates/logged_out.html" as its template

    This handler returns an **empty** context dictionary.

    :returns: a context dictionary (as described above) to be used by
        @jinja2_view to render a template.

    :rtype: dict

    """
    response.set_cookie("logged_in_as", "", path="/")
    return {}


@get('/assets/<path:path>')
def get_style_file(path):
    """Handler for GET requests to ``/assets/<path>/`` path.

    * Returns file contents of site assets. CSS, JavaScript, images,
      fonts, etc.

    **This function doesn't need to be changed.**

    """
    return static_file(path, root="assets")


# Configuration options for sessions.
# Used by alerts module
session_options = {
    'session.type': 'cookie',
    'session.validate_key': 'super-secret'
}

# Configures the app to use sessions middleware
message_app = app()
message_app = SessionMiddleware(message_app, session_options)

if __name__ == '__main__':
    # Set up a command line argument parser
    parser = argparse.ArgumentParser(
        description='Run the RocketTalk Messaging Application'
    )

    # A required --port argument, so that the user knows which port
    # they're binding to.
    parser.add_argument('--port', type=int, required=True,
                        help='The port number to listen on.')

    # Allow the user to specify a hostname, defaulting to 0.0.0.0
    # (i.e., "Bind to all network interfaces")
    parser.add_argument('--host', type=str, default="0.0.0.0",
                        help='The hostname to listen on.')

    # Parse CLI args
    args = parser.parse_args()

    # Make sure it's in the range we want
    if args.port < 8000 or args.port >= 9000:
        print("Please use a port in the range [8000, 9000).", file=sys.stderr)
        sys.exit(1)

    try:
        # Attempt to bind to the port, just to make sure that it's free
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((args.host, args.port))
        s.close()
    except OSError:
        # If it's NOT free, then it's time to bail. The user needs to
        # specify a different port number to bind to.
        fmt = "Looks like port {} is taken! Choose a different one."
        print(fmt.format(args.port), file=sys.stderr)
        sys.exit(1)

    # Run the app!
    run(
        app=message_app,                 # Use the bottle application
                                         # we made

        host=args.host, port=args.port,  # Bind to the provided
                                         # host/port

        debug=True,                      # Use debug mode (shows
                                         # helpful error pages
                                         # whenever there's a problem
                                         # with the code)

        reloader=True                    # Reload the web app whenever
                                         # a module changes
    )
