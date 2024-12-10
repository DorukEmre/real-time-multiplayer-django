let mainRoomSocket;

unreadNotifications = false;
// Global variable for userID
let g_user_id;

function closeMainRoomSocket() {
  if (mainRoomSocket && mainRoomSocket.readyState === WebSocket.OPEN) {
    // console.warn('closeMainRoomSocket > mainRoomSocket socket closed');
    mainRoomSocket.close();
  }
}

// Safe way to send messages by socket
function sendMessagesBySocket(message, socket) {

  if (g_user_id === 0 || g_user_id === '0' || g_user_id === '' || g_user_id === undefined || g_user_id === null || g_user_id === 'None' || g_user_id === '[object HTMLInputElement]') {
    // console.warn('Client is not logged in, cannot use websocket');
    return;
  }

  // console.log('sendMessagesBySocket > message:', message);
  if (socket && socket.readyState === WebSocket.OPEN) {
    socket.send(JSON.stringify(message));
    return true;
  }
  else if (socket && socket.readyState !== WebSocket.OPEN) {
    // console.error('sendMessagesBySocket > socker not ready > socket.readyState:', socket.readyState, 'socker.OPEN:', WebSocket.OPEN);
    return false;
  }
}

// Add event listener to the notification
function listenUserReadNotification() {
  const notificationDropdown = document.getElementById('navbarDropdownNotifications');
  if (notificationDropdown.hasEventListener) {
    return;
  }

  notificationDropdown.addEventListener('click', function () {
    // console.log('Notification dropdown clicked');
    unreadNotifications = false;
    const bellIcon = notificationDropdown.querySelector('img');
    if (bellIcon.src.includes('bell_up')) {
      bellIcon.src = '/media/utils_icons/bell_down.png';

      // Mark notification as read
      sendMessagesBySocket({ 'type': 'mark_notification_as_read', 'receiver_id': receiver_id }, mainRoomSocket);
    }
  }
  );
}

// Connect to the main room socket
async function connectMainRoomSocket() {
  if (!g_user_id || g_user_id === '0' || g_user_id === 0) {
    // console.error('WebSocket connection aborted: Invalid user ID');
    return;
  }

  if (mainRoomSocket && mainRoomSocket.readyState === WebSocket.OPEN) {
    // console.warn('WebSocket is already connected.');
    return;
  }

  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const hostname = window.location.hostname;
  const port = window.location.port ? `:${window.location.port}` : '';

  // console.log('Connecting to WebSocket...');
  mainRoomSocket = new WebSocket(`${protocol}//${hostname}${port}/wss/mainroom/${g_user_id}/`);

  mainRoomSocket.onopen = function (e) {
    // console.log('WebSocket connection established.');
    sendMessagesBySocket({ type: 'message', message: 'main socket opened' }, mainRoomSocket);
  };

  mainRoomSocket.onmessage = function (e) {
    const data = JSON.parse(e.data);
    parseSocketMessage(data);
  };

  mainRoomSocket.onclose = function (e) {
    // console.warn('WebSocket closed:', e);
    mainRoomSocket = null; // Reset socket reference
  };

  mainRoomSocket.onerror = function (e) {
    // console.error('WebSocket encountered an error:', e);
    mainRoomSocket.close();
  };
}

// Routine when user reload the page
window.onload = async () => {
  // Handle form submission
  handleFormSubmission();

  // Update user id global variable
  await updateUserID();

  // console.log('g_user_id:', g_user_id);
  if (g_user_id === 0 || g_user_id === '0' || g_user_id === '' || g_user_id === undefined || g_user_id === null || g_user_id === 'None' || g_user_id === '[object HTMLInputElement]') {
    // console.warn('Client is not logged in');
    return;
  }

  // Connect to the main room socket
  await connectMainRoomSocket();
}

function parseSocketMessage(data) {

  listenUserReadNotification();

  if (data.type === 'friend_request') {
    addRequestNotification(data);
    updateFriendsState();
  }
  else if (data.type === 'friend_request_response') {
    addResponseNotification(data);
    updateFriendsState();
  }
  else if (data.type === 'chat') {
    handleChatMessages(data);
  }
  else if (data.type === 'game_request') {
    addRequestNotification(data);
  }
  else if (data.type === 'game_request_response') {
    addResponseNotification(data);
  }
  else if (data.type === 'cancel_waiting_room') {
    addResponseNotification(data);
  }
  else if (data.type === 'user_connected' || data.type === 'user_left') {
    updateOnlineFriends(data);
  }
  else if (data.type === 'next_in_tournament') {
    addResponseNotification(data);
  }
  else if (data.type === 'block') {
    //console.warn('parseSocketMessage > data:', data);
    handleBlockedNotif(data);
    addRequestNotification(data);
    updateFriendsState();
  }
  else if (data.type === 'unblock') {
    //console.warn('parseSocketMessage > data:', data);
    addRequestNotification(data);
    updateFriendsState();
  }
  else if (data.type === 'game_request_unconnected') {
    addResponseNotification(data);
  }
  else {
    console.error('unknown parseSocketMessage > data', data);
  }
}