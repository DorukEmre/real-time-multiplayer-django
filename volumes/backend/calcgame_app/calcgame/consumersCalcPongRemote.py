import json, asyncio, logging
from channels.generic.websocket import AsyncWebsocketConsumer 
from .consumersCalcPongUtils import update_ball_pos, check_ball_border_collision, check_ball_paddle_collision, check_ball_outofbounds, reset_ball_position
logger = logging.getLogger(__name__)

class PongCalcRemote(AsyncWebsocketConsumer):
  # Game configuration constants
  cfg = {
    "canvas": {
      "width": 900,
      "height": 550,
    },
    "maxScore": 2,
    "ballSize": 15,
    "paddleWidth": 15,
    "paddleHeight": 80,
    "borderWidth": 15,
    "paddleSpeed": 10
  }

  def __init__(self, *args, **kwargs):
    super().__init__(*args, **kwargs)
    self.pressed_keys = set()
    # Game state
    self.gs = {
      "leftPaddleY": (self.cfg['canvas']['height'] - self.cfg['paddleHeight']) / 2,
      "rightPaddleY": (self.cfg['canvas']['height'] - self.cfg['paddleHeight']) / 2,
      "ballX": self.cfg['canvas']['width'] / 2,
      "ballY": self.cfg['canvas']['height'] / 2,
      "ballSpeedX": 6,
      "ballSpeedY": 4,
      "scorePlayer1": 0,
      "scorePlayer2": 0,
      }
    
    self.frameCount = 0;        # frame count
    self.lastContactFrame = 0;  # last frame where ball made contact with paddle
    self.pauseFrameCount = 0;   # to avoid repeat pause key press
    self.gamePaused = False;
    
  async def connect(self):
    logger.debug("PongCalcLocal > before accept")
    # Accept the WebSocket connection
    await self.accept()
    logger.debug("PongCalcLocal > Client connected")
    # Send an initial message to confirm the connection
    await self.send(text_data=json.dumps({
      'type': 'connection_established, calcgame says hello',
      'message': 'You are connected!'
    }))

  async def disconnect(self, close_code):
    # Handle WebSocket disconnection
    logger.debug("PongCalcLocal > Client disconnected")
    pass

  async def receive(self, text_data):
    # Handle messages received from the client
    data = json.loads(text_data)
    logger.debug(f"PongCalcLocal > received data: {data}")
    
    if data['type'] == 'opening_connection, game details':
      self.game_id = data['game_id']
      self.p1_name = data['p1_name']
      self.p2_name = data['p2_name']
      logger.debug(f"PongCalcLocal > Opening connection with players: {self.p1_name}, {self.p2_name}")

    if data['type'] == 'players_ready':
      logger.debug("")
      logger.debug(f"PongCalcLocal > players ready for self.game_id: {self.game_id}, data['game_id']: {data['game_id']}")
      await self.start_game(self.game_id)

    if data['type'] == 'key_press':
      # logger.debug("PongCalcLocal > key press event")
      self.update_pressed_keys(data['keys'])

  async def start_game(self, game_id):
    # Start the game and send initial game state to the client
    logger.debug("PongCalcLocal > Game started")
    for i in range(3, 0, -1):
        await self.send(text_data=json.dumps({
          'type': 'game_countdown',
          'game_id': game_id,
          'message': f'Game starting in {i}...',
          'game_state': self.gs,
          'countdown': i,
        }))
        await asyncio.sleep(0.8)

    logger.debug("PongCalcLocal > sending first game_update")
    await self.send(text_data=json.dumps({
        'type': 'game_update',
        'game_id': game_id,
        'game_state': self.gs
      }))

    # Start the game loop as a task
    self.game_task = asyncio.create_task(self.game_loop(game_id))

  async def game_end(self, game_id):
    logger.debug("PongCalcLocal > Game ended")
    winner = self.p1_name if self.gs['scorePlayer1'] > self.gs['scorePlayer2'] else self.p2_name

    # End the game
    await self.send(text_data=json.dumps({
      'type': 'game_end',
      'message': f'Game Over: {winner} wins!',
      'game_result': {
          'game_id': game_id,
          'winner': winner,
          'scorePlayer1': self.gs['scorePlayer1'],
          'scorePlayer2': self.gs['scorePlayer2'],
        }
    }))

    # Cancel the game loop task
    if hasattr(self, 'game_task'):
      self.game_task.cancel()


  async def game_loop(self, game_id):
      logger.debug("PongCalcLocal > game_loop")
      while True:
          # Wait before continuing the loop (in seconds)
          await asyncio.sleep(0.02)

          self.update_paddle_pos()

          update_ball_pos(self.gs)
          check_ball_border_collision(self.gs, self.cfg)
          check_ball_paddle_collision(self.gs, self.cfg, self.frameCount, self.lastContactFrame) # to update
          if check_ball_outofbounds(self.gs, self.cfg) == True: 
            logger.debug("PongCalcLocal > resetting ball position...")
            reset_ball_position(self.gs, self.cfg)

          # Break loop and end game if a player reaches the max score
          if self.gs['scorePlayer1'] >= self.cfg['maxScore'] or self.gs['scorePlayer2'] >= self.cfg['maxScore']:
            logger.debug("PongCalcLocal > Ending game...")
            break
          
          # Send the updated game state to the client
          await self.send(text_data=json.dumps({
              'type': 'game_update',
              'game_state': self.gs
            }))
          # logger.debug(f"Sent game_update, game_state: {self.gs}")
          
      await self.game_end(game_id)

  def update_pressed_keys(self, keys):
      # Update the set of pressed keys
      self.pressed_keys = {key: True for key in keys}

  def update_paddle_pos(self):
    if 'w' in self.pressed_keys and self.gs['leftPaddleY'] > self.cfg['borderWidth']:
        logger.debug("PongCalcLocal > update_paddle_pos > w pressed")
      # if player == 'left':
        self.gs['leftPaddleY'] -= self.cfg['paddleSpeed']
      # elif player == 'right':
      #   self.gs['rightPaddleY'] -= self.cfg['paddleSpeed']
    
    if 's' in self.pressed_keys and self.gs['leftPaddleY'] < self.cfg['canvas']['height'] - self.cfg['paddleHeight'] - self.cfg['borderWidth']:
        self.gs['leftPaddleY'] += self.cfg['paddleSpeed']

    if '8' in self.pressed_keys and self.gs['rightPaddleY'] > self.cfg['borderWidth']:
        self.gs['rightPaddleY'] -= self.cfg['paddleSpeed']

    if '5' in self.pressed_keys and self.gs['rightPaddleY'] < self.cfg['canvas']['height'] - self.cfg['paddleHeight'] - self.cfg['borderWidth']:
        self.gs['rightPaddleY'] += self.cfg['paddleSpeed']