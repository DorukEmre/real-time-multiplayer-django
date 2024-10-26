function innit_listening() {
	let friendsData = [];
	const userID = document.getElementById('userID').value;
	const chatButton = document.getElementById('chatButton');
	const contactAvatar = document.getElementById('contactAvatar');
	const contactDisplayName = document.getElementById('contactDisplayName');
	const messageInput = document.getElementById('messageInput');
	const sendButton = document.getElementById('sendButton');
	const unreadCount = document.getElementById('unreadChatsCount');
	const currentChatId = document.getElementById('currentChatId');
	const dateElement = document.getElementById('date');
	if (!dateElement) {
		console.error('dateElement not found');
	} else {
		console.log('dateElement:', dateElement);}
	let date = new Date();

	dateElement.textContent = date.toDateString();

	// Listen for the chat button click
	chatButton.addEventListener('click', function() {
		const request = new Request('/getFriends/', {
			method: 'GET',
			headers: {
				'X-CSRFToken': getCookie('csrftoken')
			},
			credentials: 'include'
		});

		// Fetch the friends
		fetch(request)
			.then(response => response.json())
			.then(data => {
				const contactList = document.getElementById('contactList');
				console.log('data:', data);
				friendsData = data.friends;

				// Clean the contact list
				contactList.innerHTML = '';

				friendsData.forEach(friend => {
					const contactItem = document.createElement('a');
					contactItem.href = '#';
					contactItem.classList.add('list-group-item', 'bg-transparent', 'text-white', 'custom-contact', 'd-flex', 'align-items-center');
					contactItem.dataset.contactId = friend.user_id;
				
					// Create avatar element
					const avatar = document.createElement('img');
					avatar.src = friend.avatar || "{% static 'images/default_avatar.png' %}";
					avatar.classList.add('rounded-circle', 'me-2');
					avatar.style.height = '2rem';
					avatar.style.width = '2rem';
					avatar.alt = 'avatar';
				
					// Create display name element
					const displayName = document.createElement('span');
					displayName.textContent = friend.display_name;
				
					// Add the avatar and display name to the contact item
					contactItem.appendChild(avatar);
					contactItem.appendChild(displayName);
				
					// Add the contact item to the contact list
					contactList.appendChild(contactItem);

					// Listen to the click event on the contact item
					contactItem.addEventListener('click', function(event) {
						// Remove the 'selected-contact' class from all contacts
						const contacts = contactList.getElementsByClassName('list-group-item');
						for (let c of contacts) {
							c.classList.remove('selected-contact');
						}
						// Add the 'selected-contact' class to the clicked contact
						contactItem.classList.add('selected-contact');

						// Update the avatar and display name
						const contactAvatarLink = document.getElementById('contactAvatarLink');
						const contactDisplayNameLink = document.getElementById('contactDisplayNameLink');
						contactAvatarLink.href = '/friend_profile/' + friend.user_id;
						contactAvatar.src = friend.avatar;
						contactDisplayName.textContent = friend.display_name;
						contactDisplayNameLink.href = '/friend_profile/' + friend.user_id;
						currentChatId.value = friend.user_id;
						
						// Get all the messages between the user and the selected friend
						data = {
							'type': 'chat',
							'subtype': 'get_conversation',
							'sender_id': userID,
							'receiver_id': friend.user_id,
						};
						sendMessagesBySocket(data, mainRoomSocket);
						// Do scroll to the bottom of the chat
						const chatMessages = document.getElementById('conversation');
						chatMessages.scrollTop = chatMessages.scrollHeight;
						console.log('chatMessages.scrollHeight:', chatMessages.scrollHeight);
						console.log('chatMessages.scrollTop:', chatMessages.scrollTop);
					});
				});
				// Update unread messages count
				data = {
					'type': 'chat',
					'subtype': 'delete_unread_messages',
					'user_id': userID,
				};
				sendMessagesBySocket(data, mainRoomSocket);
			})
			.catch(error => console.error('Error fetching friends:', error));
	});

	// Send message
	sendButton.addEventListener('click', function() {
		const selectedContact = document.querySelector('.list-group-item.selected-contact');
		if (!selectedContact) {
			console.error('No contact selected');
			return;
		} else if (!messageInput.value) {
			console.error('No message to send');
			return;
		}

		const selectedFriend = friendsData.find(friend => friend.user_id == selectedContact.dataset.contactId);
		const message = messageInput.value;
		const receiverId = selectedFriend.user_id;
		const receiverDisplayName = selectedFriend.display_name;
		const receiverAvatar = selectedFriend.avatar;
		const data = {
			'type': 'chat',
			'subtype': 'chat_message',
			'sender_id': userID,
			'receiver_id': receiverId,
			'receiver_display_name': receiverDisplayName,
			'receiver_avatar': receiverAvatar,
			'message': message,
		};
		addSentChatMessage(message);
		sendMessagesBySocket(data, mainRoomSocket);
		console.log('data:', data);
		messageInput.value = '';
	});
}

function checkUnreadMessages()
{
	const data = {
		'type': 'chat',
		'subtype': 'check_unread_messages',
		'user_id': userID,
	};
	sendMessagesBySocket(data, mainRoomSocket);
}

function handleChatMessages(data)
{
	if (data.subtype === 'innit_listening') {
		innit_listening();
		console.log('chat listen init');
	}
	else if (data.subtype === 'chat_message')
	{
		const currentChatId = document.getElementById('currentChatId');
		if (currentChatId.value == data.sender_id)
			addRecvChatMessage(data);
		checkUnreadMessages();
	}
	else if (data.subtype === 'unread_messages') {
		console.log('parseSocketMessage > data.subtype:', data.subtype);
		addUnreadMessages(data);
	} else if (data.subtype === 'load_conversation') {
		loadConversation(data);
		checkUnreadMessages();
	}

}

function loadConversation(data)
{
	console.log('loadConversation > data:', data);
	const conversation = document.getElementById('conversation');
	conversation.innerHTML = '';
	data.conversation.forEach(message => {
		if (message.sender_id == data.sender_id)
			addSentChatMessage(message.message);
		else
			addRecvChatMessage(message);
	});
}

function addSentChatMessage(message) {
	const chatMessages = document.getElementById('conversation');
	const messageElement = document.createElement('div');
	messageElement.classList.add('d-flex', 'flex-row', 'justify-content-end', 'mb-1');

	const messageContent = document.createElement('p');
	messageContent.classList.add('small', 'p-2', 'me-3', 'mb-0', 'rounded-3', 'bg-dark', 'text-white');
	messageContent.textContent = message;

	messageElement.appendChild(messageContent);
	chatMessages.appendChild(messageElement);
}

function addRecvChatMessage(data) {
	const chatMessages = document.getElementById('conversation');
	const messageElement = document.createElement('div');
	messageElement.classList.add('d-flex', 'flex-row', 'justify-content-start', 'mb-1');

	const messageContent = document.createElement('p');
	messageContent.classList.add('small', 'p-2', 'me-3', 'mb-0', 'rounded-3', 'bg-body-tertiary');
	messageContent.style.color = 'black';
	messageContent.textContent = data.message;

	messageElement.appendChild(messageContent);
	chatMessages.appendChild(messageElement);
}

function addUnreadMessages(data)
{
	const unreadChatsCount = document.getElementById('unreadChatscount');
	unreadChatsCount.textContent = data.unread_messages_count;
}