
// Start button clicked from game or tournament page
async function startRemoteGame(
    game_type, tournament_id, game_round, p1_name, p1_id, p2_name, p2_id) {
  console.log(
      game_type, tournament_id, game_round, p1_name, p1_id, p2_name, p2_id);
  // If normal game: startGame('pong', 0, 'single','Player1', 0, 'Player2', 0)
  // Tournament: startGame('pong', '3', 'Semi-Final 1', 'django_superuser',1,
  // 'Name2',0)

  // Remove the start game button and previous winner name
  document.getElementById('startGame-button')?.remove();
  document.getElementById('playAgain-button')?.remove();
  document.getElementById('nextRound-button')?.remove();
  document.getElementById('startGame-winner')?.remove();

  let game_result = {};
  // Execute the game
  if (game_type === 'pong') {
    game_result = await executeRemotePongGame(p1_name);
  } else if (game_type === 'cows') {
    game_result = await executeCowGame(p1_name, p2_name);
  }
  console.log('game_result: ', game_result);

  // Save the game result in the database
  // saveGameResultInDatabase(
  //     game_type, tournament_id, game_round, p1_name, p1_id, p2_name, p2_id,
  //     game_result);
}

async function newRemoteGame(game_type, p1_name) {
  // Set up the canvas
  const canvas = document.createElement('canvas');
  canvas.width = 900;
  canvas.height = 550;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = '#d3d3d3';  // Set the fill color
  ctx.strokeStyle = '#d3d3d3';

  const ballSize = 15
  const paddleWidth = 15
  const paddleHeight = 80
  const borderWidth = 15

  const keys =
      {w: false, s: false, 8: false, 5: false, ' ': false, Escape: false};

  function displayCanvasElement() {
    const gameContainer = document.querySelector('#game-container');
    gameContainer.innerHTML = '';
    gameContainer.appendChild(canvas);
  }

  function showCountdown(gameState, count) {
    document.querySelector('.scorePlayer1').textContent =
        gameState.scorePlayer1;
    document.querySelector('.scorePlayer2').textContent =
        gameState.scorePlayer2;

    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.font = '60px PixeloidSans';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(count, canvas.width / 2, canvas.height / 2);
  }

  // Render the game state on the canvas
  function renderGame(gameState) {
    document.querySelector('.scorePlayer1').textContent =
        gameState.scorePlayer1;
    document.querySelector('.scorePlayer2').textContent =
        gameState.scorePlayer2;

    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw center line
    let centerLineY = 0;
    while (centerLineY < canvas.height) {
      ctx.fillRect(
          canvas.width / 2, centerLineY + 0.5 * borderWidth, 1, borderWidth);
      centerLineY += 2 * borderWidth;
    }

    // Draw top and bottom borders
    ctx.fillRect(0, 0, canvas.width, borderWidth);
    ctx.fillRect(0, canvas.height - borderWidth, canvas.width, borderWidth);

    // Draw the left paddle
    ctx.fillRect(
        2 * paddleWidth, gameState.leftPaddleY, paddleWidth, paddleHeight);
    // Draw the right paddle
    ctx.fillRect(
        canvas.width - 3 * paddleWidth, gameState.rightPaddleY, paddleWidth,
        paddleHeight);

    // Draw ball
    ctx.fillRect(gameState.ballX, gameState.ballY, ballSize, ballSize);
  }

  return new Promise((resolve, reject) => {
    const gameCalcSocket = new WebSocket('/wss/calcgame/pong/remote/');
    let game_id = 0;


    function setPlayerReadyCheckBoxes(player_role) {
      const player1Ready = document.getElementById('player1-ready');
      const player2Ready = document.getElementById('player2-ready');
      if (player_role === '1') {
        player1Ready.disabled = false;
        player1Ready.addEventListener(
            'click', () => togglePlayerReady(player_role));
      } else if (player_role === '2') {
        player2Ready.disabled = false;
        player2Ready.addEventListener(
            'click', () => togglePlayerReady(player_role));
      }
    }

    function updateOpponentReadyCheckBoxes(opponent) {
      const player1Ready = document.getElementById('player1-ready');
      const player2Ready = document.getElementById('player2-ready');
      if (opponent === '1') {
        player1Ready.checked = true;
      } else if (opponent === '2') {
        player2Ready.checked = true;
      }
    }

    function togglePlayerReady(player_role) {
      const player1Ready = document.getElementById('player1-ready');
      const player2Ready = document.getElementById('player2-ready');
      if (player_role === '1' && player1Ready.checked) {
        gameCalcSocket.send(
            JSON.stringify({type: 'player_ready', player: 'player1', game_id}));
        player1Ready.disabled = true;
      } else if (player_role === '2' && player2Ready.checked) {
        gameCalcSocket.send(
            JSON.stringify({type: 'player_ready', player: 'player2', game_id}));
        player2Ready.disabled = true;
      }
    }

    gameCalcSocket.onopen = function(e) {
      //
      console.log('newRemoteGame > .onopen, connection opened.');
      gameCalcSocket.send(JSON.stringify(
          {type: 'opening_connection, my name is', p1_name: p1_name}));
    };

    gameCalcSocket.onmessage = function(e) {
      let data = JSON.parse(e.data);

      if (data.type === 'waiting_room') {
        console.log('newRemoteGame > .onmessage waiting_room:', data.message);
        // Load html waiting room
        document.querySelector('main').innerHTML = data.html;

      } else if (data.type === 'game_start') {
        console.log(
            'newRemoteGame > .onmessage game_start:', data.message,
            ' player_role:', data.player_role);
        // Load game html
        document.querySelector('main').innerHTML = data.html;
        game_id = data.game_id;
        announceGame(data.title, data.message);
        setPlayerReadyCheckBoxes(data.player_role);

      } else if (data.type === 'opponent_ready') {
        console.log('newRemoteGame > .onmessage opponent_ready:', data.message);
        updateOpponentReadyCheckBoxes(data.opponent)

      } else if (data.type === 'game_countdown') {
        console.log('newRemoteGame > .onmessage game_countdown:', data.message);
        if (data.countdown === 3) displayCanvasElement();
        showCountdown(data.game_state, data.countdown);

      } else if (data.type === 'game_update') {
        // console.log('newRemoteGame > .onmessage game_update:', data.message);
        renderGame(data.game_state);

      } else if (data.type === 'game_end') {
        console.log('newRemoteGame > .onmessage game_end:', data);
        resolve(data.game_result);
        gameCalcSocket.close();

      } else
        console.log('newRemoteGame > .onmessage data:', data);
    };

    gameCalcSocket.onclose = function(e) {
      console.log('newRemoteGame > .onclose, connection closed');
    };

    gameCalcSocket.onerror = function(e) {
      console.log('newRemoteGame > .onerror, error occurred', data);
    };
  });
}

async function findRemoteGame() {
  const game_type =
      document.querySelector('input[name="chosenGame"]:checked').id;
  const p1_name = document.getElementById('player1-input').value;

  // Check if the name is empty
  if (p1_name.length === 0 || p1_name.trim().length === 0) {
    let lang = getCookie('django_language');
    document.getElementById('error-div').style.display = 'block'
    let error = 'Name can\'t be empty';
    if (lang === 'fr')
      error = 'Le nom ne peut pas être vide';
    else if (lang === 'es')
      error = 'El nombre no puede estar vacío';
    document.querySelector('.errorlist').textContent = error;
    return;
  }

  let game_result = {};
  game_result = await newRemoteGame(game_type, p1_name);
  console.log('findRemoteGame > game_result: ', game_result);

  // Save the game result in the database
  // saveGameResultInDatabase(
  //   game_type, tournament_id, game_round, p1_name, p1_id, p2_name, p2_id,
  //   game_result);
}

function toggleRemoteMode() {
  const remoteMode = document.getElementById('remoteMode').checked;
  const player2Container = document.getElementById('form-player2');
  const player2Input = document.getElementById('player2-input');
  const button = document.getElementById('play-game-button');

  if (remoteMode) {
    player2Container.style.display = 'none';
    player2Input.required = false;
    button.textContent = 'Find remote game';
    button.setAttribute('onclick', 'findRemoteGame()');
  } else {
    player2Container.style.display = 'block';
    player2Input.required = true;
    button.textContent = 'Play game';
    button.setAttribute('onclick', 'playLocalGame()');
  }
}
