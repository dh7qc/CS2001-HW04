"""Message module

Helper functions for working with sent and received messages.

"""
import json
import os

from datetime import datetime
from glob import glob
from uuid import uuid4


DATE_FORMAT = "%Y-%m-%d %H:%M:%S"
"""The format to use for message time stamps"""


def validate_message_form(form):
    """Validates a message form in the following ways:

    * Checks that the form contains a "to" key
    * Checks that the form contains a "subject" key
    * Checks that the form contains a "body" key
    * Checks that the value of "to" is not blank
    * Checks that the value of "subject" is not blank
    * Checks that the value of "body" is not blank

    :param bottle.FormsDict form: A submitted form; retrieved from
        :class:`bottle.request`

    :returns: A list of error messages. Returning the empty list
        indicates that no errors were found.

    """
    error_list = []

    # Check if form is missing 'to'
    if 'to' not in form:
        error_list.append("Missing to field!")
    # Otherwise it does have 'to', check if it's blank
    elif len(form['to']) == 0:
        error_list.append("to field cannot be blank!")

    # Repeat above process for 'subject' and 'body'
    if 'subject' not in form:
        error_list.append("Missing subject field!")
    elif len(form['subject']) == 0:
        error_list.append("subject field cannot be blank!")

    if 'body' not in form:
        error_list.append("Missing body field!")
    elif len(form['body']) == 0:
        error_list.append("body field cannot be blank!")

    return error_list


def _load_message(message_filename):
    """Loads message data from a file.

    Messages stored as JSON-encoded objects. Message data is loaded
    and returned as dictionaries with the following attributes:

    * **id** (:class:`str`) - The ID of the message. The same as
      its filename. Note that we **do not** store the id in the
      file. It is derived from the file name and added to the loaded
      message before we return it.

    * **to** (:class:`str`) - The username of the message recipient

    * **from** (:class:`str`) - The username of the message sender

    * **subject** (:class:`str`) - The subject of the message

    * **body** (:class:`str`) - The body of the message

    * **time** (:class:`datetime.datetime`) - The time when the
      message was sent

    :param str message_filename: The path of the file that stores the
        JSON-encoded message data. The name of the file have the form
        ``<uuid>.json``, where ``<uuid>`` is a unique ID:
        https://en.wikipedia.org/wiki/Universally_unique_identifier

    :returns: A loaded message dict as described above

    """

    dict = {}

    with open(message_filename) as f:
        # Load the json file
        msg = json.load(f)

        # Derives the uuid from message_filename
        dict['id'] = message_filename[9:45]

        # Get the rest of the data
        dict['to'] = msg['to']
        dict['from'] = msg['from']
        dict['subject'] = msg['subject']
        dict['body'] = msg['body']

        # Converts the time string to the correct type and format
        dict['time'] = datetime.strptime(msg['time'], DATE_FORMAT)

    return dict


def load_message(message_id):
    """Loads a single message from the ``messages/`` directory.

    Uses the ID of a message to construct a file path, and uses
    :func:`message._load_message` to load and return the message data.

    :returns: A list of loaded messages ordered by timestamp from
        most to least recent.

    """

    # Create the directory from which _load_message will open the file.
    file_name = os.path.join('messages/', '{}.json'.format(message_id))

    # Use _load_message to get that file's contents into a dict.
    msg_dict = _load_message(file_name)

    # Assuming it's supposed to return the dict and NOT a list.
    return msg_dict


def load_all_messages():
    """Loads all messages from the ``messages/`` directory.

    Uses :func:`message._load_message` and `glob.glob
    <https://docs.python.org/3.4/library/glob.html#glob.glob>`_ to
    create a new list of loaded messages. Messages are sorted
    according to their timestamp, so that the returned list starts
    with the most recent message and ends with the least recent.

    :returns: A list of loaded messages ordered by timestamp from
        most to least recent.

    """
    lst = []

    # Open each json file in messages directory
    for file in glob('messages/*.json'):

        # Load message into dict and append to list
        dict = _load_message(file)
        lst.append(dict)

    # Sort the list by the time key from most to least recent.
    lst = sorted(lst, key=lambda x: x['time'], reverse=True)

    return lst


def load_sent_messages(username):
    """Loads all messages from the ``messages/`` directory that were
    **sent** by the specified user.

    Uses :func:`message._load_message` and `glob.glob
    <https://docs.python.org/3.4/library/glob.html#glob.glob>`_ to
    create a new list of loaded messages. Messages are sorted
    according to their timestamp, so that the returned list starts
    with the most recent message and ends with the least recent.

    The returned list container *only* messages that were sent by the
    specified user.

    :param str username: The sender we're filtering for

    :returns: A list of loaded messages (sent by ``username``) ordered
        by timestamp from most to least recent.

    """
    lst = []

    # Open each json file in messages directory
    for file in glob('messages/*.json'):
        # Load message, append to list if 'from' matches username
        dict = _load_message(file)
        if dict['from'] == username:
            lst.append(dict)
        else:
            continue

    # Sort the list by the time key from most to least recent.
    lst = sorted(lst, key=lambda x: x['time'], reverse=True)

    return lst


def load_received_messages(username):
    """Loads all messages from the ``messages/`` directory that were
    **received** by the specified user.

    Uses :func:`message._load_message` and `glob.glob
    <https://docs.python.org/3.4/library/glob.html#glob.glob>`_ to
    create a new list of loaded messages. Messages are sorted
    according to their timestamp, so that the returned list starts
    with the most recent message and ends with the least recent.

    The returned list container *only* messages that were received by
    the specified user.

    :param str username: The receiver we're filtering for

    :returns: A list of loaded messages (received by ``username``) ordered
        by timestamp from most to least recent.

    """
    lst = []

    # Open each json file in messages directory
    for file in glob('messages/*.json'):
        # Load message, append to list if 'to' matches username
        dict = _load_message(file)
        if dict['to'] == username:
            lst.append(dict)
        else:
            continue

    # Sort the list by the time key from most to least recent.
    lst = sorted(lst, key=lambda x: x['time'], reverse=True)

    return lst


def send_message(message_dict):
    """Saves a message to the ``messages/`` directory.

    The message dict contains the following fields:

    * **to** (:class:`str`) - The username of the message recipient

    * **from** (:class:`str`) - The username of the message sender

    * **subject** (:class:`str`) - The subject of the message

    * **body** (:class:`str`) - The body of the message

    * **time** (:class:`str`) - The time the message was sent

    The saved file is named uniquely by generating a UUID with
    Python's built-in `uuid.uuid4()
    <https://docs.python.org/3.4/library/uuid.html#uuid.uuid4>`_
    function. We won't have to worry about accidentally overwriting
    files that way.

    The dictionary converted to a JSON-encoded string and saved to a
    file. The saved file has the name ``<uuid>.json`` (where
    ``<uuid>`` is a UUID) and is stored in the ``messages/``
    directory.

    :param dict message_dict: A dictionary containing message
        information as described above.

    :raises OSError: If there's a problem writing to the file. Files
        are opened for `exclusive creation.
        <https://docs.python.org/3.4/library/functions.html#open>`_

    :returns: None

    """

    # Generate a uuid
    new_uuid = uuid4()

    # Define the save directory and file name
    file = os.path.join('messages/', '{}.json'.format(new_uuid))

    # Create the file and dump the message_dict to it.
    with open(file, 'x') as outfile:
        json.dump(message_dict, outfile, indent=4)
