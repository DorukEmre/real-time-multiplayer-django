function listenForm(form) {
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    console.warn('Form submitted', e);

    // console.log('Form submitted', e);

    const formData = new FormData(form);
    let url = form.action;

    const jsonObject = {};
    formData.forEach((value, key) => {
      jsonObject[key] = value;
    });
    console.log('jsonObject: ', jsonObject);
    try {
      // console.log('url: ', url);
      let request = new Request(url, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',
          'Content-Type': 'application/json',
          'X-CSRFToken': getCookie('csrftoken')
        },
        credentials: 'include',
        body: JSON.stringify(jsonObject)
      });
      console.log('handleFormSubmission > request: ', request);
      const response = await fetch(request);
      const data = await response.json();

      console.log('handleFormSubmission > response: ', response);

      if (!response.ok && !data.html.includes('class="errorlist nonfield')) {
        throw new Error(`HTTP error - status: ${response.status}`);
      }
      console.log('listenForm > data: ', data);
      console.log(
        'listenForm > data.preferred_language ', data.preferred_language);
      console.log('listenForm > data.message: ', data.message);
      console.log('listenForm > data.html: ', data.html);
      if (data.status != 'error' && data.message && !data.html) {
        console.log('data.message: ', data.message);
        if (data.message === 'Login successful') {
          sessionStorage.setItem('afterLogin', 'true');
        } else if (data.message === 'Sign up successful') {
          sessionStorage.setItem('afterSignup', 'true');
        } else if (data.message === 'Profile updated') {
          sessionStorage.setItem('afterProfileUpdate', 'true');
        }
        if (data.message !== 'Profile updated') {
          window.location.replace('/');
        }
      } else
        document.querySelector('main').innerHTML = data.html;

      if (data.message === 'Invitation to play sent!') {
        inviteFriendToPlay(data.sender_username, data.sender_id, data.sender_avatar_url, data.receiver_id)
      }

      if (!data?.html?.includes('class="errorlist nonfield')) {
        if (data.message != 'starting Semi-Final 1')
          displayMessageInModal(data.message);
        else
          announceGame(
            document.querySelector('h1').textContent,
            `${document.getElementById('namePlayer1').textContent} vs ${document.getElementById('namePlayer2').textContent}`);
      }
      handleFormSubmission();
    } catch (error) {
      console.error('Form submission error:', error);
      document.querySelector('main').innerHTML =
        '<h1>Form submission error</h1>';
    }
  });
}

function listenFormUpload(form) {
  console.log('form: ', form);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    // console.log('Form submitted', e);
    const formData = new FormData(form);
    let url = form.action;

    try {
      // Create a new request for file upload
      let request = new Request(url, {
        method: 'POST',
        headers: {
          'X-Requested-With': 'XMLHttpRequest',  // To identify as AJAX request
          'X-CSRFToken': getCookie('csrftoken')  // If CSRF token is required
        },
        credentials: 'include',  // Include cookies (if necessary)
        body: formData           // FormData handles the file and other fields
        // automatically
      });

      // Send the request and wait a response
      const response = await fetch(request);
      const data = await response.json();

      console.log('handleFormSubmission > response: ', response);

      if (!response.ok && response.status == 400) {
        // window.location.replace('/edit_profile');
        // displayMessageInModal('No file selected');
      }

      else if (!response.ok) {
        console.error('HTTP error - status:', response.status);
        throw new Error(`HTTP error - status: ${response.status}`);
      }

      // Handle the response data
      if (data.status != 'error' && data.message) {
        console.log('data.message: ', data.message);
      } else
        document.querySelector('main').innerHTML = data.html;
      if (!data?.html?.includes('class="errorlist nonfield')) {
        displayMessageInModal(data.message);
      }
      handleFormSubmission();

    } catch (error) {
      console.error('Form submission error:', error);
      document.querySelector('main').innerHTML =
        '<h1>Form submission error</h1>';
    }
  });
}
async function handleFormSubmission() {
  const form = document.querySelector('form');
  const formUpload = document.getElementById('file-upload')
  const formGeneral = document.getElementById('type-general')
  const formSecurity = document.getElementById('type-security')
  const modalInviteFriend = document.getElementById('inviteFriendModal')
  const formFriendInvite = document.getElementById('type-invite-friend')
  // Select all forms by their class name
  var forms = document.querySelectorAll('form[id^="invite-play-"]'); // Select forms by unique ID pattern

  // Iterate over each form and add an event listener
  forms.forEach(function (form) {
    listenForm(form)
  });



  if (modalInviteFriend && formFriendInvite) {
    console.log('modalInviteFriend && formFriendInvite');
    listenFriendInvitation(modalInviteFriend, formFriendInvite);
  }
  else if (formUpload) {
    listenFormUpload(formUpload);
  }
  else if (form) {
    listenForm(form);
  }

  if (formGeneral) {
    listenForm(formGeneral);
  }

  if (formSecurity) {
    listenForm(formSecurity);
  }
}
