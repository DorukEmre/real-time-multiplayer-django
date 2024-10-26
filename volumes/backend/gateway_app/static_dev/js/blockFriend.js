function blockFriend() {
	const blockSwitch = document.getElementById('blockSwitch');

	blockSwitch.addEventListener('change', async function () {
		const userId = blockSwitch.getAttribute('data-user-id');
		const checked = blockSwitch.checked;
		console.log('userId:', userId);
		console.log('checked:', checked);
		if (checked) {
			const request = new Request(`/blockFriend/${userId}/`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': getCookie('csrftoken'),
                },
            });
			try {
				const response = await fetch(request);
				if (!response.ok) {
					throw new Error('HTTP error, status = ' + response.status);
				}
				const data = await response.json();
				console.log('data:', data);
			} catch (error) {
				console.error('Error:', error);
			}
		}
	});
}

document.addEventListener('DOMContentLoaded', blockFriend);