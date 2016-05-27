'use strict';
const messageList = new MessageList();
ko.applyBindings(messageList, document.getElementById('message-list'));
const user = new UserViewModel(messageList);
ko.applyBindings(user, document.getElementById('user'));
const receiver = new ReceiverViewModel(user);
ko.applyBindings(receiver, document.getElementById('receiver'));
