import os, json, logging, websockets, ssl, asyncio, requests, aiohttp
from channels.generic.websocket import AsyncWebsocketConsumer
from django.template.loader import render_to_string
from django.middleware.csrf import get_token
#from ppretty import ppretty
logger = logging.getLogger(__name__)

logger = logging.getLogger(__name__)
logging.getLogger('websockets').setLevel(logging.WARNING)

# On connect, adds self to waiting
# If 2 players in waiting, starts a game. Tracked in active_games
# self.active_games = {
            # "game_id": {
            #     "game_type": 'pong' or 'cows',
            #     "player1": {
            #         "channel_name": "channel_name",
            #         "player_name": "player_name",
            #         "player_id": "player_id",
            #         "ws": "ws",
            #         "context": "context",
            #         "ready": False,
            #     },
            #     "player2": { ... },
            #     "calcgame_ws": "calcgame_ws",
            #     "calcgame_task": "calcgame_task",
        # }

class ProxyCalcGameRemote(AsyncWebsocketConsumer):
    active_games = {} # Dictionary to store active games
    waiting = {} # Dictionary to store players waiting for a game

    # Add check 
    # user should not be able to play against themselves through two remote games

    async def connect(self):
        logger.debug("ProxyCalcGameRemote > connect")
        await self.accept()
        
        # Extract the query selector from the WebSocket URL
        query_selector = self.scope['query_string'].decode('utf-8')
        if '=' in query_selector and len(query_selector.split('=')) > 1:
            game_type = query_selector.split('=')[1]
        else:
            game_type = None
        
        if game_type == None or game_type not in ['pong', 'cows']:
            logger.error("ProxyCalcGameRemote > No game_type provided, connection closed")
            await self.close()
            return
        
        # Generate a unique player ID for this connection
        connect_id = self.channel_name
        context = {
            'user': self.scope['user'],
            'session': self.scope['session'],
            'cookies': self.scope['cookies'],
        }

        if game_type not in self.waiting:
            self.waiting[game_type] = {}
        
        self.waiting[game_type][connect_id] = {
            'channel_name': self.channel_name,
            'player_name': None,
            'player_id': 0,
            'ws': self,
            'context': context,
        }
        
        logger.debug(f"Player connected and added to waiting: {connect_id}")

        await self.waiting_room()
        
        self.check_waiting_task = asyncio.create_task(self.check_waiting(game_type))

    async def check_waiting(self, game_type):
        while True:
            if game_type in self.waiting:
                # Filter players with player_name not None
                filtered_players = {k: v for k, v in self.waiting[game_type].items() if v['player_name'] is not None}

                # logger.debug(ppretty(filtered_players, indent='  ', width=80))

                if len(filtered_players) >= 2:
                    # Pop two players from filtered_players
                    player1_id, player1 = filtered_players.popitem()
                    player2_id, player2 = filtered_players.popitem()

                    # Remove the popped players from waiting
                    self.waiting[game_type].pop(player1_id)
                    self.waiting[game_type].pop(player2_id)

                    # Generate a unique game ID
                    game_id = f"game_{len(self.active_games) + 1}"

                    # Add the game to the active_games dictionary
                    self.active_games[game_id] = {
                        "game_type": player1['game_type'],
                        "player1": player1,
                        "player2": player2,
                    }

                    # logger.debug(f"ProxyCalcGameRemote > Two players connected, starting with ID: {game_id}")
                    # logger.debug(f"ProxyCalcGameRemote > start_game player1: {player1}")
                    # logger.debug(f"ProxyCalcGameRemote > start_game player2: {player2}")
                    await asyncio.sleep(2)
                    await self.start_game(game_id)
                else:
                    await asyncio.sleep(1)
            else:
                await asyncio.sleep(1)

    async def start_game(self, game_id):
        logger.debug("")
        logger.debug(f"ProxyCalcGameRemote > start_game game_id: {game_id}")
        game = self.active_games[game_id]
        player1 = game['player1']
        player2 = game['player2']
        logger.debug(f"ProxyCalcGameRemote > start_game player1: {player1}")
        logger.debug(f"ProxyCalcGameRemote > start_game player2: {player2}")

        # logger.debug(f"ProxyCalcGameRemote > start_game p1 context: {player1['context']}")
        # logger.debug(f"ProxyCalcGameRemote > start_game p2 context: {player2['context']}")
        info = {
            'tournament_id': 0,
            'game_round': 'single',
            'game_type': game['game_type'],
            'p1_name': player1['player_name'],
            'p2_name': player2['player_name'],
            'p1_id': player1['player_id'],
            'p2_id': player2['player_id'],
        }
        html1 = render_to_string('fragments/game_remote_fragment.html', {'context': player1['context'], 'info': info})
        # logger.debug(f"ProxyCalcGameRemote > start_game html1: {html1}")
        html2 = render_to_string('fragments/game_remote_fragment.html', {'context': player1['context'], 'info': info})

        try: # Notify players that the game is starting            
            await player1['ws'].send(json.dumps({
                'type': 'game_start',
                'game_id': game_id,
                'title': 'Game starting...', # to translate
                'message': 'You are the player on the left', # to translate
                'player_role': '1',
                'html': html1,
            }))

            await player2['ws'].send(json.dumps({
                'type': 'game_start',
                'game_id': game_id,
                'title': 'Game starting...', # to translate
                'message': 'You are the player on the right', # to translate
                'player_role': '2',
                'html': html2,
            }))
            
        except Exception as e:
            logger.error(f"ProxyCalcGameRemote > start_game Error notifying players: {e}")

        # Create an SSL context that explicitly trusts the calcgame certificate
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(os.getenv("CERTFILE"))

        # Establish the WebSocket connection with the calcgame service
        calcgame_ws = await websockets.connect(
            f"wss://calcgame:9004/pongcalc_consumer/remote/{game['game_type']}/",
            ssl=ssl_context
        )

        # # Start listening for messages from calcgame
        calcgame_task = asyncio.create_task(self.listen_to_calcgame(game_id))

        # Store the WebSocket connection and task in the active_games dictionary
        self.active_games[game_id]['calcgame_ws'] = calcgame_ws
        self.active_games[game_id]['calcgame_task'] = calcgame_task


    async def disconnect(self, close_code):
        logger.debug("ProxyCalcGameRemote > disconnect")

        connect_id = self.channel_name

        # Remove the player from the appropriate waiting[game_type] list if they exist
        for game_type, waiting_players in self.waiting.items():
            if connect_id in waiting_players:
                del waiting_players[connect_id]
                logger.debug(f"Player {connect_id} disconnected and removed from waiting[{game_type}]")
                break  # Stop once the player is found and removed

        # Close the WebSocket connection to the calcgame service if it exists
        if hasattr(self, 'calcgame_ws'):
            await self.calcgame_ws.close()

        # Cancel the background task listening to calcgame if it exists
        if hasattr(self, 'calcgame_task'):
            self.calcgame_task.cancel()


    async def receive(self, text_data):
        # Handle messages received from the client
        logger.debug(f"ProxyCalcGameRemote > receive from {self.channel_name}")
        logger.debug(f"ProxyCalcGameRemote > receive from client: {text_data}")
        data = json.loads(text_data)
        connect_id = self.channel_name

        if data['type'] == 'opening_connection, my name is':
            # Client confirms connection with their player name
            game_type = data['game_type']
            if connect_id in self.waiting[game_type]:
                player = self.waiting[game_type][connect_id]
                player['player_name'] = data['p1_name']
                player['ready'] = False
                player['game_type'] = game_type
                if self.scope['user'].is_authenticated:
                  player['player_id'] = self.scope['user'].id

                logger.debug(f"Updated waiting[{game_type}][{connect_id}] with player_name: {data['p1_name']}, player_id: {self.waiting[game_type][connect_id]['player_id']}")
            else:
                logger.error(f"Player {connect_id} not found in waiting")

        elif data['type'] == 'player_ready':
            game = self.active_games[data['game_id']]
            
            # Mark player as ready
            if connect_id == game['player1']['channel_name']:
                game['player1']['ready'] = True
            elif connect_id == game['player2']['channel_name']:
                game['player2']['ready'] = True

            # notify other player that this player is ready
            if connect_id == game['player1']['channel_name']:
                await game['player2']['ws'].send(json.dumps({
                    'type': 'opponent_ready',
                    'game_id': data['game_id'],
                    'opponent': '1',
                }))
            elif connect_id == game['player2']['channel_name']:
                await game['player1']['ws'].send(json.dumps({
                    'type': 'opponent_ready',
                    'game_id': data['game_id'],
                    'opponent': '2',
                }))
            logger.debug(f"player1 ready: {game['player1']['ready']}, player2 ready: {game['player2']['ready']}")

            # If both players are ready, notify calcgame
            if game['player1']['ready'] and game['player2']['ready']:
                await game['calcgame_ws'].send(
                    json.dumps({
                        'type': 'players_ready',
                        'game_id': data['game_id'],
                    })
                )
            
        else:
            # Forward client message to calcgame websocket
            if data['game_id'] and data['game_id'] in self.active_games and 'calcgame_ws' in self.active_games[data['game_id']]:
                calcgame_ws = self.active_games[data['game_id']]['calcgame_ws']
                await calcgame_ws.send(text_data)

    async def listen_to_calcgame(self, game_id):
        try:
            while True:
                # Continuously receive messages from calcgame
                calcgame_ws = self.active_games[game_id]['calcgame_ws']
                calcgame_response = await calcgame_ws.recv()
                data = json.loads(calcgame_response)
                
                if not data['type'] == 'game_update' and data['message']:
                    logger.debug(f"ProxyCalcGameLocal > from calcgame: {data['message']}")
                    
                if data['type'] == 'connection_established, calcgame says hello':
                    # Connection established with calcgame, send back game info
                    text_data = json.dumps({
                        'type': 'opening_connection, game details',
                        'game_id': game_id,
                        'p1_name': self.active_games[game_id]['player1']['player_name'],
                        'p2_name': self.active_games[game_id]['player2']['player_name'],
                    })
                    await calcgame_ws.send(text_data)

                    # Send message received from calcgame to both players
                    player1 = self.active_games[game_id]['player1']
                    player2 = self.active_games[game_id]['player2']
                    await player1['ws'].send(calcgame_response)
                    await player2['ws'].send(calcgame_response)       

                elif data['type'] == 'game_end':
                    # Game ended
                    await self.game_end(game_id, calcgame_response)
                    break

                else:
                    # Send message received from calcgame to both players
                    player1 = self.active_games[game_id]['player1']
                    player2 = self.active_games[game_id]['player2']
                    await player1['ws'].send(calcgame_response)
                    await player2['ws'].send(calcgame_response)                

        except websockets.exceptions.ConnectionClosed:
            logger.debug("ProxyCalcGameRemote > calcgame connection closed")
            pass

    async def waiting_room(self):
        logger.debug("ProxyCalcGameRemote > player in waiting_room")

        context = {
            'user': self.scope['user'],
            'session': self.scope['session'],
            'cookies': self.scope['cookies'],
        }
        html = render_to_string('fragments/waiting_room.html', context=context)

        await self.send(json.dumps({
            'type': 'waiting_room',
            'message': 'Waiting for another player to join...',
            'html': html,
        }))

    async def game_end(self, game_id, calcgame_response):
        logger.debug(f"ProxyCalcGameRemote > game_end game_id: {game_id}")
        game = self.active_games[game_id]
        player1 = game['player1']
        player2 = game['player2']
        dataCalcgame = json.loads(calcgame_response)
        game_result = dataCalcgame.get('game_result')

        # Update winner name with actual name
        if game_result.get('game_winner_name') == 'p1_name':
            game_result['game_winner_name'] = player1['player_name']
        else:
            game_result['game_winner_name'] = player2['player_name']

        # Save game to database
        await self.save_game_to_database(game_id, game, player1, player2, game_result)

        # Notify players that the game has ended and send game_end html
        html1 = render_to_string('fragments/game_end_fragment.html', {
              'context': player1['context'],
              'game_result': game_result
            })
        html2 = render_to_string('fragments/game_end_fragment.html', {
              'context': player2['context'],
              'game_result': game_result
            })

        dataCalcgame['html'] = html1
        await player1['ws'].send(json.dumps(dataCalcgame))

        dataCalcgame['html'] = html2
        await player2['ws'].send(json.dumps(dataCalcgame))


    async def save_game_to_database(self, game_id, game, player1, player2, game_result):
        logger.debug(f"ProxyCalcGameRemote > save_game_to_database game_id: {game_id}")
        # Save game to database
        play_url = 'https://play:9003/api/saveGame/'

        csrf_token = player1['context']['cookies'].get('csrftoken')        
        headers = {
            'X-CSRFToken': csrf_token,
            'Cookie': f'csrftoken={csrf_token}',
            'Content-Type': 'application/json',
            'Referer': 'https://gateway:8443',
        }
        
        data = {
            'game_type': 'pong',
            'game_round': 'single',
            'p1_name': player1['player_name'],
            'p2_name': player2['player_name'],
            'p1_id': player1['player_id'],
            'p2_id': player2['player_id'],
            'p1_score': game_result.get('p1_score'),
            'p2_score': game_result.get('p2_score'),
            'game_winner_name': player1['player_name'] if game_result.get('game_winner_name') == 'p1_name' else player2['player_name'],
            'game_winner_id': player1['player_id'] if game_result.get('game_winner_name') == 'p1_name' else player2['player_id'],
        }
        
        ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ssl_context.load_verify_locations(os.getenv("CERTFILE"))

        # async http request to save game in play container
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(play_url, json=data, headers=headers, ssl=ssl_context) as response:
                    # Check if response status is 200 OK
                    if response.status == 200:
                        response_json = await response.json()
                        logger.debug(f"ProxyCalcGameRemote > calcgame responds: {response_json.get('message')}")
                    else:
                        logger.error(f"ProxyCalcGameRemote > Failed to save game. Status code: {response.status}")
            except aiohttp.ClientError as e:
                logger.error(f"ProxyCalcGameRemote > Error during request: {e}")

        # Close the websocket connection to the calcgame service
        await game['calcgame_ws'].close()
        logger.debug(f"ProxyCalcGameRemote > calcgame_ws closed")

        # Remove the game from active_games
        self.active_games.pop(game_id)
        logger.debug("ProxyCalcGameRemote > game removed from active_games")
