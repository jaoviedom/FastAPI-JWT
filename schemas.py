def individual_user(user) -> dict:
    return {
        "id": str(user["_id"]),
        "username": user["username"],
        "email": user["email"],
        "full_name": user["full_name"],
        "hashed_password": user["hashed_password"],
        "disabled": user["disabled"]
    }

def list_users(users) -> list:
    return[individual_user(user) for user in users]