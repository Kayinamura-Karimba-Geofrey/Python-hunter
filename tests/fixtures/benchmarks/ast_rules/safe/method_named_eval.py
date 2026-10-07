# expect: none


class Model:
    def eval(self) -> "Model":
        return self


def predict(model: Model) -> Model:
    return model.eval()
