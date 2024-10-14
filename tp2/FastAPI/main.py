from fastapi import FastAPI, Path
import uvicorn
import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

instance_id = os.getenv('INSTANCE_ID', 'unknown')

# Create FastAPI app
app = FastAPI()


@app.get("/{path:path}")
async def catch_all(path: str = Path(...)):
    message = f"Instance {instance_id} has received the request for path: {path}"
    logger.info(message)
    return {"message": message}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
