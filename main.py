import os
import sys
import redis
import dotenv
from flask import Flask, jsonify
import logging
import uuid
import requests
import json
from textwrap import dedent

from theoriq import AgentDeploymentConfiguration, ExecuteContext, ExecuteResponse
from theoriq.api.v1alpha1.schemas import ExecuteRequestBody
from theoriq.biscuit import TheoriqCost
from theoriq.dialog import TextItemBlock
from theoriq.extra.flask.v1alpha1.flask import theoriq_blueprint
from theoriq.types import Currency

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

# Initialize Redis client
redis_client = redis.Redis(
    host=os.getenv('REDIS_HOST'),
    port=os.getenv('REDIS_PORT'),
    password=os.getenv('REDIS_PASSWORD'),
)

BASE_URL = "https://dao-voting-agent-b33e.onrender.com/"

def generate_session_token():
    """Generate a unique session token."""
    return str(uuid.uuid4())

def get_session_token(context: ExecuteContext):
    """Get or create a session token for the current user."""
    session_key = f"session:{context.request_sender_address}"
    session_token = redis_client.get(session_key)
    if not session_token:
        session_token = generate_session_token()
        redis_client.set(session_key, session_token)
    return session_token.decode() if isinstance(session_token, bytes) else session_token

def validate_proposal_format(input_text: str):
    """Validate and parse proposal input format."""
    try:
        # Split input by required fields
        title_split = input_text.split('Title:')
        if len(title_split) != 2:
            return None, "Input must start with 'Title:'"
        
        # Extract and clean data after 'Title:'
        remaining_text = title_split[1]
        
        # Split description
        desc_split = remaining_text.split('Description:')
        if len(desc_split) != 2:
            return None, "Missing 'Description:' field"
            
        title = desc_split[0].strip()
        if not title:
            return None, "Title cannot be empty"
            
        # Split private key
        remaining_text = desc_split[1]
        key_split = remaining_text.split('Private Key:')
        if len(key_split) != 2:
            return None, "Missing 'Private Key:' field"
            
        description = key_split[0].strip()
        private_key = key_split[1].strip()
        
        if not description:
            return None, "Description cannot be empty"
        if not private_key:
            return None, "Private Key cannot be empty"
            
        return {
            "title": title,
            "description": description,
            "private_key": private_key
        }, None
    except Exception as e:
        logger.error(f"Error validating proposal format: {str(e)}")
        return None, "Error validating input format"

def validate_vote_format(input_text: str):
    """Validate and parse vote input format."""
    try:
        # Split input by required fields
        id_split = input_text.split('Proposal ID:')
        if len(id_split) != 2:
            return None, "Input must start with 'Proposal ID:'"
        
        # Extract remaining text
        remaining_text = id_split[1]
        
        # Split private key
        key_split = remaining_text.split('Private Key:')
        if len(key_split) != 2:
            return None, "Missing 'Private Key:' field"
            
        proposal_id = key_split[0].strip()
        private_key = key_split[1].strip()
        
        if not proposal_id.isdigit():
            return None, "Proposal ID must be a number"
        if not private_key:
            return None, "Private Key cannot be empty"
            
        return {
            "proposal_id": str(proposal_id),
            "private_key": private_key
        }, None
    except Exception as e:
        logger.error(f"Error validating vote format: {str(e)}")
        return None, "Invalid format"


def validate_history_format(input_text: str):
    """Validate wallet address format."""
    import re
    try:
        # Strip any leading/trailing whitespace from the input
        address = input_text.strip()
        
        if not address:
            return None, "Wallet address cannot be empty"
        
        # Validate wallet address format (42 characters, starting with '0x')
        if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
            return None, "Invalid wallet address format. It should be a 42-character ID starting with '0x'."
        
        return {
            'address': address
        }, None
    except Exception as e:
        logger.error(f"Error validating history format: {str(e)}")
        return None, "Invalid format for wallet address"
    
def get_available_commands():
    """Get list of available commands."""
    return dedent("""
        Available commands:
        1. /create_proposal - Create a new proposal
        2. /get_proposals - View all current proposals
        3. /vote - Vote on an existing proposal
        4. /vote_history - View your voting history
        5. /chat - Chat about the DAO and proposals
        6. /balance - Check your wallet balance
        7. /proposal_history - View your proposal creation history
        8. /chat_proposal - Chat about a specific proposal by ID
        9. /help - Show this help message
    """).strip()

def format_success_response(message: str):
    """Format success response with available commands."""
    return f"{message}\n\n{get_available_commands()}"

def get_user_state(session_token: str):
    """Get the current state for a user session."""
    try:
        state = redis_client.get(f"user_state:{session_token}")
        if state:
            return json.loads(state.decode('utf-8'))
        return None
    except Exception as e:
        logger.error(f"Error getting user state: {str(e)}")
        return None

def set_user_state(session_token: str, state: dict):
    """Set the state for a user session."""
    try:
        redis_client.set(f"user_state:{session_token}", json.dumps(state))
    except Exception as e:
        logger.error(f"Error setting user state: {str(e)}")

def handle_hello():
    """Handle the hello/welcome message."""
    return dedent("""
        Welcome to the DAO Voting Agent! 👋

        I can help you interact with the DAO voting system. Here are the available commands:

        1. /create_proposal - Create a new proposal
           Format: [title, description, private_key]

        2. /get_proposals - View all current proposals

        3. /vote - Vote on an existing proposal
           Format: [proposal_id, private_key]

        4. /vote_history - View your voting history
           Format: [wallet_address]

        5. /chat - Chat about the DAO and proposals
           Just type your message normally!
           
        6. /balance - Check your wallet balance
           Format: [wallet_address]

        7. /proposal_history - View your proposal creation history
           Format: [wallet_address]

        8. /chat_proposal - Chat about a specific proposal by ID
           Format: [wallet_address, message, proposal_id]

        9. /help - Show this help message

        To get started, simply type one of the commands above.
    """).strip()

def handle_create_proposal(input_text: str, session_state):
    """Handle the create proposal workflow."""
    if not session_state:
        return dedent("""
            Please provide the proposal details in the following format:

            Title: Your proposal title
            Description: Your detailed proposal description. This can be multiple lines and include commas, periods, etc.
            Private Key: Your private key

            Example:
            Title: Community Cleanup Initiative
            Description: A proposal to organize a community-wide cleanup event to improve sanitation and environmental conditions.
            Private Key: 0x123...

            Type /cancel to return to the main menu.
        """).strip()
    
    try:
        if input_text.lower() == '/cancel':
            return format_success_response("Command cancelled.")

        # Parse the input
        proposal_data, error = validate_proposal_format(input_text)
        if error:
            return error
        
        if not proposal_data:
            return "Invalid format. Please provide all required fields: Title, Description, and Private Key."
            
        # Log the parsed data for debugging
        logger.info(f"Parsed proposal data: {proposal_data}")
        logger.info(f"Parsed data type: {type(proposal_data)}")
        
        # Debug: Print the full URL being used
        full_url = f"{BASE_URL}proposals"
        logger.info(f"Making request to URL: {full_url}")
        
        # Debug: Print the exact data being sent
        logger.info(f"Request payload: {json.dumps(proposal_data, indent=2)}")

        # Call the API with debug logging
        try:
            response = requests.post(
                full_url,
                json=proposal_data,
                headers={'Content-Type': 'application/json'}  # Explicitly set content type
            )
            
            # Debug: Print response details
            logger.info(f"Response status code: {response.status_code}")
            logger.info(f"Response headers: {dict(response.headers)}")
            logger.info(f"Response content: {response.text}")
            
            if response.status_code == 200:
                return format_success_response(f"Proposal created successfully! Transaction hash: {response.json()['transaction_hash']}")
            return format_success_response(f"Error creating proposal: {response.json().get('detail', 'Unknown error')}")
            
        except requests.exceptions.RequestException as req_err:
            logger.error(f"Request error: {str(req_err)}")
            return format_success_response(f"Error making API request: {str(req_err)}")

    except Exception as e:
        logger.error(f"Error in handle_create_proposal: {str(e)}")
        return format_success_response(f"Error processing proposal details: {str(e)}")

def handle_vote(input_text: str, session_state):
    """Handle the voting workflow."""
    if not session_state:
        return dedent("""
            Please provide the voting details in the following format:

            Proposal ID: The ID of the proposal you want to vote on
            Private Key: Your private key

            Example:
            Proposal ID: 1
            Private Key: 0x123...

            Type /cancel to return to the main menu.
            Type /view_proposals to see available proposals.
        """).strip()
    
    try:
        if input_text.lower() == '/cancel':
            return format_success_response("Command cancelled.")
        elif input_text.lower() == '/view_proposals':
            return handle_get_proposals()

        # Parse the input
        vote_data, error = validate_vote_format(input_text)
        if error:
            return error
        
        if not vote_data:
            return "Please provide all required fields: Proposal ID and Private Key."
        
        # Log the parsed data for debugging
        logger.info(f"Parsed vote data: {vote_data}")
        logger.info(f"Parsed data type: {type(vote_data)}")
        
        # Debug: Print the full URL being used
        full_url = f"{BASE_URL}vote"
        logger.info(f"Making request to URL: {full_url}")
        
        # Debug: Print the exact data being sent
        logger.info(f"Request payload: {json.dumps(vote_data, indent=2)}")
        
        response = requests.post(
            f"{BASE_URL}vote",
            json=vote_data,
            headers={'Content-Type': 'application/json'}  # Explicitly set content type
        )
        
        if response.status_code == 200:
            return format_success_response(f"Vote cast successfully! Transaction hash: {response.json()['transaction_hash']}")
        return format_success_response(f"Error casting vote: {response.json().get('detail', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Error in handle_vote: {str(e)}")
        return format_success_response(f"Error processing vote details: {str(e)}")
    
def handle_get_proposals():
    """Handle retrieving all proposals."""
    try:
        response = requests.get(f"{BASE_URL}proposals")
        if response.status_code == 200:
            proposals = response.json()['proposals']
            if not proposals:
                return format_success_response("No proposals found.")
            
            result = "Current Proposals:\n\n"
            for prop in proposals:
                result += dedent(f"""
                    Proposal ID: {prop['proposal_id']}
                    Title: {prop['title']}
                    Description: {prop['description']}
                    Vote Count: {prop['vote_count']}
                    Executed: {prop['executed']}
                    Creator: {prop['creator']}
                    
                    ------------------------
                """)
            return format_success_response(result)
        return format_success_response(f"Error fetching proposals: {response.json().get('detail', 'Unknown error')}")
    except Exception as e:
        return format_success_response(f"Error retrieving proposals: {str(e)}")

def handle_vote_history(input_text: str, session_state):
    """Handle retrieving vote history."""
    if not session_state:
        return dedent("""
            Please enter your wallet address to view your voting history:
            
            "(Note: It should be a 42-character ID starting with '0x'.)"

            Type /cancel to return to the main menu.
        """).strip()
    
    try:
        if input_text.lower() == '/cancel':
            return format_success_response("Command cancelled.")

        # Parse and validate the input
        address_data, error = validate_history_format(input_text)
        if error:
            return error
        
        if not address_data:
            return "Please provide a valid wallet address."

        response = requests.post(
            f"{BASE_URL}vote_history",
            json=address_data
        )
        
        if response.status_code == 200:
            history = response.json()
            if not history['voted_proposal_ids']:
                return format_success_response("You haven't voted on any proposals yet.")
            return format_success_response(f"You have voted on the following proposal IDs: {', '.join(map(str, history['voted_proposal_ids']))}")
        return format_success_response(f"Error retrieving vote history: {response.json().get('detail', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Error in handle_vote_history: {str(e)}")
        return format_success_response(f"Error processing address: {str(e)}")

def handle_chat(input_text: str, session_state):
    """Handle chatting about proposals."""
    if not session_state:
        return dedent("""
            What would you like to know about the DAO and its proposals?
            
            You can ask about:
            - Current proposals
            - Voting processes
            - DAO governance
            - Or anything else about the DAO!

            Type /exit to return to the main menu.
        """).strip()
    
    if input_text.lower() == '/exit':
        return format_success_response("Exiting chat mode.")
    
    try:
        response = requests.post(
            f"{BASE_URL}chat",
            json={"message": input_text}
        )
        
        if response.status_code == 200:
            # Don't add available commands for chat responses unless exiting
            return f"{response.json()['reply']}\n\nType /exit to return to the main menu."
        return f"Error processing chat: {response.json().get('detail', 'Unknown error')}"

    except Exception as e:
        return f"Error processing chat message: {str(e)}"
    
def validate_balance_format(input_text: str):
    """Validate wallet address format for balance check."""
    import re
    try:
        address = input_text.strip()
        
        if not address:
            return None, "Wallet address cannot be empty"
        
        if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
            return None, "Invalid wallet address format. It should be a 42-character ID starting with '0x'."
        
        return {
            'address': address
        }, None
    except Exception as e:
        logger.error(f"Error validating balance format: {str(e)}")
        return None, "Invalid format for wallet address"

def validate_proposal_history_format(input_text: str):
    """Validate wallet address format for proposal history."""
    import re
    try:
        address = input_text.strip()
        
        if not address:
            return None, "Wallet address cannot be empty"
        
        if not re.match(r"^0x[a-fA-F0-9]{40}$", address):
            return None, "Invalid wallet address format. It should be a 42-character ID starting with '0x'."
        
        return {
            'address': address
        }, None
    except Exception as e:
        logger.error(f"Error validating proposal history format: {str(e)}")
        return None, "Invalid format for wallet address"
    

def handle_balance(input_text: str, session_state):
    """Handle checking wallet balance."""
    if not session_state:
        return dedent("""
            Please enter your wallet address to check your balance:
            
            (Note: It should be a 42-character ID starting with '0x'.)

            Type /cancel to return to the main menu.
        """).strip()
    
    try:
        if input_text.lower() == '/cancel':
            return format_success_response("Command cancelled.")

        address_data, error = validate_balance_format(input_text)
        if error:
            return error
        
        if not address_data:
            return "Please provide a valid wallet address."

        response = requests.post(
            f"{BASE_URL}balance",
            json=address_data
        )
        
        if response.status_code == 200:
            balance = response.json()['balance']
            return format_success_response(f"Your balance is: {balance} ETH")
        return format_success_response(f"Error retrieving balance: {response.json().get('detail', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Error in handle_balance: {str(e)}")
        return format_success_response(f"Error processing address: {str(e)}")
    
def handle_proposal_history(input_text: str, session_state):
    """Handle retrieving proposal creation history."""
    if not session_state:
        return dedent("""
            Please enter your wallet address to view your proposal creation history:
            
            (Note: It should be a 42-character ID starting with '0x'.)

            Type /cancel to return to the main menu.
        """).strip()
    
    try:
        if input_text.lower() == '/cancel':
            return format_success_response("Command cancelled.")

        address_data, error = validate_proposal_history_format(input_text)
        if error:
            return error
        
        if not address_data:
            return "Please provide a valid wallet address."

        response = requests.post(
            f"{BASE_URL}proposal_history",
            json=address_data
        )
        
        if response.status_code == 200:
            history = response.json()
            if not history['proposal_ids']:
                return format_success_response("You haven't created any proposals yet.")
            return format_success_response(f"You have created the following proposal IDs: {', '.join(map(str, history['proposal_ids']))}")
        return format_success_response(f"Error retrieving proposal history: {response.json().get('detail', 'Unknown error')}")

    except Exception as e:
        logger.error(f"Error in handle_proposal_history: {str(e)}")
        return format_success_response(f"Error processing address: {str(e)}")

def validate_proposal_chat_format(input_text: str):
    """Validate and parse proposal chat input format."""
    try:
        # Split input by required fields
        id_split = input_text.split('Proposal ID:')
        if len(id_split) != 2:
            return None, "Input must start with 'Proposal ID:'"
        
        remaining_text = id_split[1]
        
        # Split wallet
        wallet_split = remaining_text.split('Wallet:')
        if len(wallet_split) != 2:
            return None, "Missing 'Wallet:' field"
            
        proposal_id = wallet_split[0].strip()
        
        # Split message
        remaining_text = wallet_split[1]
        message_split = remaining_text.split('Message:')
        if len(message_split) != 2:
            return None, "Missing 'Message:' field"
            
        wallet = message_split[0].strip()
        message = message_split[1].strip()
        
        # if not proposal_id.isdigit():
        #     return None, "Proposal ID must be a number"
        if not wallet:
            return None, "Wallet cannot be empty"
        if not message:
            return None, "Message cannot be empty"
            
        return {
            "proposal_id": str(proposal_id),
            "wallet": wallet,
            "message": message
        }, None
    except Exception as e:
        logger.error(f"Error validating proposal chat format: {str(e)}")
        return None, "Invalid format"

def handle_proposal_chat(input_text: str, session_state):
    """Handle chatting about a specific proposal."""
    if not session_state:
        return dedent("""
            Please provide the chat details in the following format:

            Proposal ID: The ID of the proposal you want to discuss
            Wallet: Your wallet address
            Message: Your message about the proposal

            Example:
            Proposal ID: 1
            Wallet: 0x123...
            Message: What are the implications of this proposal?

            Type /cancel to return to the main menu.
            Type /view_proposals to see available proposals.
        """).strip()
    
    try:
        if input_text.lower() == '/cancel':
            return format_success_response("Command cancelled.")
        elif input_text.lower() == '/view_proposals':
            return handle_get_proposals()

        # Parse and validate the input
        chat_data, error = validate_proposal_chat_format(input_text)
        if error:
            return error
        
        if not chat_data:
            return "Please provide all required fields: Proposal ID, Wallet, and Message."
        
        # Make API request
        response = requests.post(
            f"{BASE_URL}chat/proposal_by_id",
            json=chat_data,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code == 200:
            # Return just the reply without available commands list
            return response.json()['reply']
        return f"Error processing chat: {response.json().get('detail', 'Unknown error')}"

    except Exception as e:
        logger.error(f"Error in handle_proposal_chat: {str(e)}")
        return format_success_response(f"Error processing chat: {str(e)}")

def execute(context: ExecuteContext, req: ExecuteRequestBody) -> ExecuteResponse:
    """Main execution function for Theoriq Agent"""
    try:
        logger.info(f"Received request: {context.request_id}")
        
        # Get the input text from request
        last_block = req.last_item.blocks[0]
        input_text = last_block.data.text.strip()
        
        # Get session token
        session_token = get_session_token(context)
        
        # Get session state
        current_state = get_user_state(session_token)
        
        logger.info(f"Session token: {session_token}")
        logger.info(f"Current state: {current_state}")
        logger.info(f"Input received: {input_text}")
        
        input_lower = input_text.lower()
        
        # Handle different commands
        try:
            if input_lower in ['hello', 'hi', 'hey']:
                response_text = handle_hello()
                redis_client.delete(f"user_state:{session_token}")
            elif input_lower == '/create_proposal':
                response_text = handle_create_proposal(input_text, None)
                set_user_state(session_token, {"command": "create_proposal"})
            elif input_lower == '/vote':
                response_text = handle_vote(input_text, None)
                set_user_state(session_token, {"command": "vote"})
            elif input_lower == '/get_proposals':
                response_text = handle_get_proposals()
                redis_client.delete(f"user_state:{session_token}")
            elif input_lower == '/vote_history':
                response_text = handle_vote_history(input_text, None)
                set_user_state(session_token, {"command": "vote_history"})
            elif input_lower == '/chat':
                response_text = handle_chat(input_text, None)
                set_user_state(session_token, {"command": "chat"})
            elif input_lower == '/balance':
                response_text = handle_balance(input_text, None)
                set_user_state(session_token, {"command": "balance"})
            elif input_lower == '/proposal_history':
                response_text = handle_proposal_history(input_text, None)
                set_user_state(session_token, {"command": "proposal_history"})
            elif input_lower == '/chat_proposal':
                response_text = handle_proposal_chat(input_text, None)
                set_user_state(session_token, {"command": "chat_proposal"})
            elif input_lower == '/help':
                response_text = get_available_commands()
                redis_client.delete(f"user_state:{session_token}")
            else:
                # Handle ongoing conversations based on session state
                if current_state and "command" in current_state:
                    if current_state["command"] == "create_proposal":
                        response_text = handle_create_proposal(input_text, current_state)
                    elif current_state["command"] == "vote":
                        response_text = handle_vote(input_text, current_state)
                    elif current_state["command"] == "vote_history":
                        response_text = handle_vote_history(input_text, current_state)
                    elif current_state["command"] == "chat":
                        response_text = handle_chat(input_text, current_state)
                        if input_text.lower() != '/exit':
                            # Keep chat state active unless explicitly exited
                            set_user_state(session_token, current_state)
                    elif current_state["command"] == "balance":
                        response_text = handle_balance(input_text, current_state)
                    elif current_state["command"] == "proposal_history":
                        response_text = handle_proposal_history(input_text, current_state)
                    elif current_state["command"] == "chat_proposal":
                        response_text = handle_proposal_chat(input_text, current_state)
                        if input_text.lower() != '/exit':
                            # Keep chat state active unless explicitly exited
                            set_user_state(session_token, current_state)
                    else:
                        response_text = "Unknown command state. Type 'hello' for available commands."
                        redis_client.delete(f"user_state:{session_token}")
                else:
                    response_text = "I don't understand that command. Type 'hello' for a list of available commands."

        except Exception as e:
            logger.error(f"Error processing command: {str(e)}")
            response_text = "An error occurred processing your command. Please try again or type 'hello' for available commands."

        return context.new_response(
            blocks=[TextItemBlock(text=response_text)],
            cost=TheoriqCost(amount=1, currency=Currency.USDC),
        )

    except Exception as e:
        logger.error(f"Error in execute function: {str(e)}")
        return context.new_response(
            blocks=[TextItemBlock(text="An error occurred. Please try again or type 'hello' for available commands.")],
            cost=TheoriqCost(amount=1, currency=Currency.USDC),
        )
        
def create_app():
    """Create and configure the Flask application"""
    app = Flask(__name__)
    
    # Load agent configuration from env
    dotenv.load_dotenv()
    agent_config = AgentDeploymentConfiguration.from_env()
    
    # Create and register theoriq blueprint
    blueprint = theoriq_blueprint(agent_config, execute)
    app.register_blueprint(blueprint)
    
    return app

# Create the Flask application instance
app = create_app()

@app.route("/")
def home():
    return jsonify({"message": "Welcome to the DAO Voting Agent"})

if __name__ == "__main__":
    print("Starting Flask server...", flush=True)
    app.run(host="0.0.0.0", port=8000, debug=True)