function displayError(errorMessage) {
  document.getElementById('error-div').style.display = 'block';
  document.querySelector('.errorlist').textContent = errorMessage;
}

function checkValidInputGame(gameMode, gameType, p1_name, p2_name) {
  let lang = getCookie('django_language');

  // Check if the gameMode and gameType are valid
  if (!gameMode || !gameType ||
    (gameMode !== 'local' && gameMode !== 'remote') ||
    (gameType !== 'pong' && gameType !== 'cows')) {
    let error = 'Invalid selection';
    if (lang === 'fr')
      error = 'Sélection invalide';
    else if (lang === 'es')
      error = 'Selección inválida';
    displayError(error);

    return false;
  }

  // Check if the names are empty or only whitespace
  if ((p1_name.length === 0 || p1_name.trim().length === 0) ||
    (gameMode === 'local' &&
      (p2_name.length === 0 || p2_name.trim().length === 0))) {
    let error = 'Name can\'t be empty';
    if (lang === 'fr')
      error = 'Le nom ne peut pas être vide';
    else if (lang === 'es')
      error = 'El nombre no puede estar vacío';
    displayError(error);

    return false;
  }

  // Check if the names are different
  if (gameMode === 'local' && (p1_name === p2_name)) {
    let error = 'Names must be different';
    if (lang === 'fr')
      error = 'Les noms doivent être différents';
    else if (lang === 'es')
      error = 'Los nombres deben ser diferentes';
    displayError(error);

    return false;
  }

  // Check name length <= 16
  if (p1_name.length > 16 || (gameMode === 'local' && p2_name.length > 16)) {
    let error = 'Name must be 16 characters or less';
    if (lang === 'fr')
      error = 'Le nom doit comporter 16 caractères ou moins';
    else if (lang === 'es')
      error = 'El nombre debe tener 16 caracteres o menos';
    displayError(error);

    return false;
  }

  // Check if names are alphanumerical
  if (!/^[a-zA-Z0-9_]+$/i.test(p1_name) ||
    (gameMode === 'local' && !/^[a-zA-Z0-9_]+$/i.test(p2_name))) {
    let error = 'Names must be alphanumerical';
    if (lang === 'fr')
      error = 'Les noms doivent être alphanumériques';
    else if (lang === 'es')
      error = 'Los nombres deben ser alfanuméricos';
    displayError(error);

    return false;
  }

  return true;
}

// Toggles what's displayed depending on the game mode
function toggleGameMode() {
  const remoteMode = document.getElementById('remoteMode').checked;
  const player2Container = document.getElementById('form-player2');
  const player2Input = document.getElementById('player2-input');
  const button = document.getElementById('play-game-button');

  if (remoteMode) {
    player2Container.style.display = 'none';
    player2Input.required = false;
    button.textContent = 'Find remote game';
    // button.setAttribute('onclick', 'findRemoteGame()');
  } else {
    player2Container.style.display = 'block';
    player2Input.required = true;
    button.textContent = 'Play game';
    // button.setAttribute('onclick', 'playLocalGame()');
  }
}

// Called from button on Play page, starts a new game
async function playGame() {
  // gameMode: 'local' or 'remote' (or 'ai)
  // gameType: 'pong' or 'cows'

  let gameMode = document.querySelector('input[name="gameMode"]:checked').id;
  if (gameMode === 'localMode') gameMode = 'local';
  if (gameMode === 'remoteMode') gameMode = 'remote';

  const gameType =
    document.querySelector('input[name="chosenGame"]:checked').id;

  const p1_name = document.getElementById('player1-input').value;
  let p2_name = '';
  if (gameMode === 'local') {
    p2_name = document.getElementById('player2-input').value;
  }

  // check input selection
  if (!checkValidInputGame(gameMode, gameType, p1_name, p2_name)) return;

  // gameRound: 'single', 'Semi-Final 1', 'Semi-Final 2', 'Final'
  let gameRound = 'single';

  startNewGame(gameMode, gameType, gameRound, p1_name, p2_name);
}