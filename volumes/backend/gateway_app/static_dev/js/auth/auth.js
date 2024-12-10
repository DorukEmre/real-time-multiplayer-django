
async function updateUserID() {
  try {
    const response = await fetch('/api/getUserID/', { credentials: 'include' });
    const data = await response.json();
    if (data.user_id) {
      g_user_id = data.user_id;
      // console.log('Updated global user ID:', g_user_id);
    } else {
      // console.error('Failed to retrieve user ID');
      g_user_id = null;
    }
  } catch (error) {
    // console.error('Error fetching user ID:', error);
    g_user_id = null;
  }
}

async function handleRefresh(type) {
  // console.warn('handleRefresh called by:\n', new Error().stack.split('\n')[2].trim());
  // First GET request for the main content
  // console.log('handleRefresh > type:', type);

  if (type != 'language') {
    // console.log('handleRefresh > main content');
    await fetch(`/home/?status=success&message=Logged%20in%20successfully&type=main`, {
      headers: {
        'X-CSRFToken': getCookie('csrftoken'),
        'x-requested-with': 'XMLHttpRequest',
      },
      credentials: 'include'
    })
      .then(response => response.json())
      .then(data => {
        if (data.status === 'success') {
          document.querySelector('main').innerHTML = data.html;
        }
      })
      .catch(error => {
        console.error('Error:', error);
      });
  }


  // Second GET request for the header content
  // console.log('handleRefresh > header');
  await fetch(`/home/?status=success&message=Logged%20in%20successfully&type=header`, {
    headers: {
      'X-CSRFToken': getCookie('csrftoken'),
      'x-requested-with': 'XMLHttpRequest',
    },
    credentials: 'include'
  })
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        document.querySelector('header').innerHTML = data.html;
        // get the div with id 'userID' and replace its value with the new user id. Example <input type="hidden" id="userID" value="1">
        if (type == 'logout') {
          g_user_id = 0;
        }
        else {
          // console.log(data.user_id)
          g_user_id = data.user_id;
          // console.log(g_user_id)
        }
      }
    })
    .catch(error => {
      console.error('Error:', error);
    });

  let chatPresent = false;
  // Remove chat on logout and language change
  if (type == 'logout' || type == 'language' || type == 'profile_update') {
    // console.log('handleRefresh > remove chat');
    // remove chat element
    const chatSection = document.getElementById('chatSection');
    if (chatSection) {
      chatSection.remove();
      if (type != 'logout') {
        chatPresent = true;
      }
    }
    const chatButton = document.getElementById('chatButton');
    if (chatButton) {
      chatButton.remove();
    }
  }

  // Add chat
  if (type == 'login' || type == 'refresh' || type == 'signup' || chatPresent) {
    // console.log('handleRefresh > add chat');
    // GET request for chat section
    fetch(`/home/?status=success&message=Logged%20in%20successfully&type=chat`, {
      headers: {
        'X-CSRFToken': getCookie('csrftoken'),
        'x-requested-with': 'XMLHttpRequest',
      },
      credentials: 'include'
    })
      .then(response => response.json())
      .then(data => {
        if (data.status === 'success') {
          // console.log('Adding chat section');
          document.querySelector('body').innerHTML += data.html;

          // Initialise the chat modal
          const chatModalElement = document.getElementById('chatModal');
          const chatModal = new bootstrap.Modal(chatModalElement);
          chatModal.hide();
          init_listening();

          if (type == 'profile_update') {
            let lang = getCookie('django_language');
            // console.log('handleRefresh > lang:', lang);
            let message = 'Profile updated';
            if (lang === 'fr')
              message = 'Profil mis à jour';
            else if (lang === 'es')
              message = 'Perfil actualizado';
            displayMessageInModal(message);
          }

        }
      })
      .catch(error => {
        console.error('Error:', error);
      });

  }

  if (type != 'logout') {
    if (!mainRoomSocket || mainRoomSocket.readyState != WebSocket.OPEN) {
      connectMainRoomSocket();
    }
  }

  if (type != 'language') {
    window.history.pushState({}, '', '/');
  }

  if (type == 'profile_update' || type == 'login' || type == 'refresh' || type == 'signup' || chatPresent) {
    // console.warn('handleRefresh > updating notifications');
    await fetchTranslations();
    if (mainRoomSocket && mainRoomSocket.readyState != WebSocket.OPEN) {
      connectMainRoomSocket();
    }
    if (mainRoomSocket && mainRoomSocket.readyState === WebSocket.OPEN) {
      reloadNotificationsIfNeeded();
    }
  }
}


function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}


function enable2FA() {
  fetch('/enable2FA/', {
    method: 'POST',
    headers: {
      'X-CSRFToken': getCookie('csrftoken'),
      'Content-Type': 'application/json'
    },
  })
    .then(response => response.json())
    .then(data => {
      const twoFaButtonEnable = document.getElementById('2fa-button-enable');
      twoFaButtonEnable.style.display = 'none';
      const qrCodeDiv = document.getElementById('2fa-qr-code');
      qrCodeDiv.style.display = 'flex';
      qrCodeDiv.innerHTML = data.html

      if (data.status === 'success') {
        qrCodeDiv.removeChild(document.getElementById('2fa-enable-error'));
      } else {
        qrCodeDiv.removeChild(document.getElementById('2fa-enable-success'));
      }
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('2fa-qr-code').innerHTML = '<p class="text-danger">Failed to enable 2FA. Please try again later.</p>';
    });
}

function confirm2FA() {
  const otpCode = document.getElementById('otp-code').value;
  if (!otpCode) {
    const error = `<p class="alert alert-danger">${document.getElementById('otp-code').placeholder}</p>`;
    document.getElementById('otp-code').insertAdjacentHTML('beforebegin', error);
    return;
  }

  fetch('/confirm2FA/', {
    method: 'POST',
    headers: {
      'X-CSRFToken': getCookie('csrftoken'),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ otp_code: otpCode })
  })
    .then(response => response.json())
    .then(data => {

      const qrCodeDiv = document.getElementById('2fa-qr-code');
      if (data.status === 'success') {
        const twoFaButtonDisable = document.getElementById('2fa-button-disable');
        twoFaButtonDisable.style.display = 'block';
        qrCodeDiv.innerHTML = `<p class="text-success p-2 m-0">${data.message}</p>`;
      } else {
        const twoFaButtonDisable = document.getElementById('2fa-button-enable');
        twoFaButtonDisable.style.display = 'block';
        qrCodeDiv.innerHTML = `<p class="text-danger p-2 m-0">${data.message}</p>`;
      }
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('2fa-qr-code').innerHTML = '<p class="text-danger">Failed to confirm 2FA. Please try again later.</p>';
    });
}

function verify2FA() {
  // Get the OTP code entered by the user
  const otpCode = document.getElementById('otp_code').value;

  // Retrieve the user ID from the hidden div
  const userId = document.getElementById('config2FA').getAttribute('user-id-2fa');

  // Make a POST request to the URL with the appended user ID
  fetch(`/verify2FA/${userId}/`, {
    method: 'POST',
    headers: {
      'X-CSRFToken': getCookie('csrftoken'),
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ otp_code: otpCode })
  })
    .then(response => response.json())
    .then(async data => {
      const messageDiv = document.getElementById('2fa-message');

      if (data.status === 'success') {
        messageDiv.innerHTML = `<p class="text-success">${data.message}</p>`;
        refreshToken();
        await sleep(200);
        await handleRefresh('login');
        await connectMainRoomSocket();
      } else {
        messageDiv.innerHTML = `<p class="text-danger">${data.message}</p>`;
      }
    })
    .catch(error => {
      console.error('Error:', error);
      const messageDiv = document.getElementById('2fa-message');
      messageDiv.innerHTML = '<p class="text-danger">Verification failed. Please try again later.</p>';
    });
}

function disable2FA() {
  fetch('/disable2FA/', {
    method: 'POST',
    headers: {
      'X-CSRFToken': getCookie('csrftoken'),
      'Content-Type': 'application/json'
    },
  })
    .then(response => response.json())
    .then(data => {
      if (data.status === 'success') {
        const twoFaButtonEnable = document.getElementById('2fa-button-enable');
        twoFaButtonEnable.style.display = 'block';
        const twoFaButtonDisable = document.getElementById('2fa-button-disable');
        twoFaButtonDisable.style.display = 'none';

        document.getElementById('2fa-qr-code').innerHTML = `<p class="text-success p-2 m-0">${data.message}</p>`;
      } else if (data.error) {
        document.getElementById('2fa-qr-code').innerHTML = `<p class="text-danger p-2 m-0">${data.message}</p>`;
      }
    })
    .catch(error => {
      console.error('Error:', error);
      document.getElementById('2fa-qr-code').innerHTML = '<p class="text-danger">Failed to disable 2FA. Please try again later.</p>';
    });
}

document.addEventListener("DOMContentLoaded", async () => {
  await refreshToken();
  // Set interval to refresh token every 50 seconds
  setInterval(async () => {
    try {
      const newToken = await refreshToken();
      // console.log("Token refreshed");
    } catch (error) {
      // console.error("Failed to refresh token:", error);
      // Handle token refresh failure (e.g., redirect to login)
    }
  }, 20 * 10000); // 200 seconds
});

async function refreshToken() {
  try {
    const response = await fetch('/api/refresh-token/', {
      method: 'POST',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'Content-Type': 'application/json',
        'X-CSRFToken': getCookie('csrftoken')
      },
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error("Failed to refresh token");
    }

    const data = await response.json();

    // check for the message variable in the response body if its == 'Expired Token refreshed'
    if (data.message === 'Expired Token refreshed') {
      // console.log("Expired Token refreshed");
      await sleep(300);
      await handleRefresh("refresh");
    }

    // Assuming the new token is in data.token
    return data.token;
  } catch (error) {
    // console.error("Error refreshing token:", error);
    throw error;
  }
}
