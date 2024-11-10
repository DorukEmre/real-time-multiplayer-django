
// Show modal before tournament game
function announceGame(round, message) {
  let messageModal =
      new bootstrap.Modal(document.getElementById('messageModal'));
  messageModal.show();
  document.getElementById('messageModalLabel').innerText = round;
  document.getElementById('messageContent').innerText = message;
  document.getElementById('messageContent').classList.remove('text-end');
  document.getElementById('messageContent').classList.add('text-center');
}
// Show message modal
function displayMessageInModal(message) {
  if (message) {
    console.log('displayMessageInModal > message: ', message);
    let messageModal =
        new bootstrap.Modal(document.getElementById('messageModal'));
    messageModal.show();
    document.getElementById('messageModalLabel').innerText = notificationMsg;
    document.getElementById('messageContent').innerText = message;
    document.getElementById('messageContent').classList.remove('text-center');
    document.getElementById('messageContent').classList.add('text-end');
  }
}

// Get value of a cookie
function getCookie(name) {
  let cookieValue = null;
  if (document.cookie && document.cookie !== '') {
    let cookies = document.cookie.split(';');
    for (let i = 0; i < cookies.length; i++) {
      let cookie = cookies[i].trim();
      if (cookie.substring(0, name.length + 1) === (name + '=')) {
        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
        break;
      }
    }
  }
  return cookieValue;
}
 // Prevents the dropdown from closing
document.addEventListener('DOMContentLoaded', () => {
  const notificationContent = document.getElementById('notificationContent');
  
  if (notificationContent) {
    notificationContent.addEventListener('click', (event) => {
      event.stopPropagation();
    });
  }
});

function askUserToReload() {
  const reload = confirm('Connection lost. Please reload the page');
  if (reload) {
    location.reload();
  }
}

function reconnectSocket(socket) {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const hostname = window.location.hostname;
  const port = window.location.port ? `:${window.location.port}` : '';
  console.log('sendMessagesBySocket > reconnecting to the socket..')

  // Reconnect to the corresponding socket
  if (socket === mainRoomSocket) {
    console.log('sendMessagesBySocket > reconnecting to the mainRoomSocket');
    const userID = document.getElementById('userID').value;
    console.log('userID:', userID);
    if (userID === 0 || userID === '0' || userID === '' || userID === undefined || userID === null || userID === 'None' || userID === '[object HTMLInputElement]') {
      console.warn('Client is not logged in');
      return false;
    }
    socket = new WebSocket(`${protocol}//${hostname}${port}/wss/mainroom/${userID}/`);
  }
  else if (socket === inviteFriendSocket) {
    console.log('sendMessagesBySocket > reconnecting to the inviteFriendSocket');
    socket = new WebSocket(`${protocol}//${hostname}${port}/wss/invite_friend/`);
  }

  // Check the socket state
  if (socket.readyState === WebSocket.OPEN) {
    console.log('sendMessagesBySocket > socket reconnected successfully');
    return true;
  }
  else {
    askUserToReload();
    console.log('sendMessagesBySocket > socket failed to reconnect');
    return false;
  }
}