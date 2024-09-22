from fastapi import FastAPI
import uvicorn
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

instance_id = os.getenv('INSTANCE_ID', 'unknown')

# Create FastAPI app
app = FastAPI()


@app.get("/")
async def root():
    message = f"Instance {instance_id} has received the request"
    logger.info(message)
    return {"message": message}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
