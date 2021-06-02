import { Router } from "express";

import { AuthenticateController } from "@modules/accounts/useCases/authenticateUser/AuthenticateUserController";

const authenticateRoutes = Router();

const authenticateUserController = new AuthenticateController();

authenticateRoutes.post("/sessions", authenticateUserController.handle);

export { authenticateRoutes };
