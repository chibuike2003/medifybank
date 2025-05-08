import random
import os
from base58 import b58encode
from solana.keypair import Keypair
from solana.rpc.api import Client
from models import User
from mnemonic import Mnemonic

# ✅ Word list for generating mimephrase
word_list = [
"sun", "moon", "star", "light", "dark", "sky", "earth", "fire", "ocean", "wind", "cloud", "tree", "stone", "river", "dream", "storm", "shadow", "spark", "voice", "echo",
"wave", "mountain", "valley", "sea", "sand", "forest", "hill", "lake", "night", "day", "life", "death", "birth", "growth", "decay", "hope", "fear", "joy", "sorrow",
"path", "journey", "destination", "home", "family", "friend", "love", "hate", "peace", "war", "calm", "chaos", "serenity", "turmoil", "beauty", "ugliness", "truth", "lie",
"memory", "forgetfulness", "past", "present", "future", "time", "space", "matter", "energy", "body", "mind", "spirit", "soul", "heart", "brain", "thought", "emotion", "action",
"flower", "bird", "fish", "animal", "insect", "plant", "fruit", "vegetable", "mineral", "rock", "soil", "water", "air", "earthquake", "volcano", "tornado", "hurricane", "tsunami",
"laughter", "tears", "smile", "frown", "song", "dance", "music", "art", "poetry", "story", "history", "culture", "tradition", "community", "society", "civilization",
"atom", "molecule", "cell", "organism", "ecosystem", "universe", "galaxy", "starlight", "blackhole", "comet", "meteor", "asteroid", "planet", "moonlight", "solarflare",
"computer", "software", "hardware", "algorithm", "data", "information", "knowledge", "wisdom", "intelligence", "artificial", "machine", "learning", "neural", "network",
"city", "town", "village", "country", "nation", "state", "province", "district", "neighborhood", "street", "avenue", "road", "highway", "freeway", "bridge", "tunnel",
"car", "truck", "bus", "train", "plane", "boat", "ship", "bicycle", "motorcycle", "scooter", "skateboard", "wheelchair", "spaceship", "rocket", "satellite", "drone"
]


# ✅ Generate a unique 4-word mimephrase
def generate_unique_mimephrase():
    while True:
        phrase = "-".join(random.sample(word_list, 15))  # 15 unique random words
        existing = User.query.filter_by(mimephrase=phrase).first()
        if not existing:
            return phrase

# ✅ Generate a 12-word mnemonic (seed) phrase
def generate_mnemonic():
    mnemo = Mnemonic("english")
    return mnemo.generate(strength=128)  # 12 words

# ✅ Generate unique 10-digit account number
def generate_unique_account_number():
    while True:
        account_number = ''.join([str(random.randint(0, 9)) for _ in range(10)])
        existing = User.query.filter_by(account_number=account_number).first()
        if not existing:
            return account_number

# ✅ Generate Solana wallet (public & base58 private key)
def generate_solana_wallet():
    keypair = Keypair()
    public_key = str(keypair.public_key)
    private_key = b58encode(keypair.secret_key).decode('utf-8')  # For secure storage
    return public_key, private_key

# ✅ Get Solana balance using public key
def get_solana_balance(pubkey):
    client = Client(os.getenv("SOLANA_RPC"))
    try:
        response = client.get_balance(pubkey)
        lamports = response['result']['value']
        return lamports / 1e9  # Convert from lamports to SOL
    except Exception as e:
        print("Error getting balance:", e)
        return 0.0
