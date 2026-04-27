import { generateToken, verifyToken } from "../../src/services/token.services";

describe("token.service", () => {
    test("retourner une string", () => {
        const userId = "123";
        const token = generateToken(userId);

        expect(typeof token).toBe("string");
    });

    test("retourner le bon userID", () => {
        const userId = "123";
        const token = generateToken(userId);
        const resultat = verifyToken(token);
        console.log(resultat);
        expect(resultat).toEqual(expect.objectContaining({userId: "123"}));
    });

    test("verifyToken doit lancer une erreur si token invalide", () => {
        expect(() => verifyToken("token_bidon")).toThrow();
    });
});