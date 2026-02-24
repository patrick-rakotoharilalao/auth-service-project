import { ForbiddenError } from "@/errors";
import { Role } from "@/generated/prisma/enums";
import { NextFunction, Request, Response } from "express";

export const requireAdmin = (req: Request, res: Response, next: NextFunction) => {
    const user = req.user as any;

    if (user.role !== Role.ADMIN) {
        throw new ForbiddenError('Admin access required');
    }

    next();
};