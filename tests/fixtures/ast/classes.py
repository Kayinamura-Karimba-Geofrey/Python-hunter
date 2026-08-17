class BaseService:
    pass

class UserService(BaseService):
    def get_user(self, user_id: int):
        return {"id": user_id}
