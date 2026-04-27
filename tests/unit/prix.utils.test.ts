import { calculerPrix } from "../../src/utils/prix.utils"

describe("calculerPrix", () => {

    test("Cas normal avec 20% de remise", () => {
        const prixBase = 100;
        const remise = 20;
        const resultat = calculerPrix(prixBase, remise); // ← pas de () =>
        expect(resultat).toBe(80);                       // ← toBe, pas toThrow
    });

    test("Cas normal sans remise", () => {
        const prixBase = 100;
        const remise = 0;
        const resultat = calculerPrix(prixBase, remise);
        expect(resultat).toBe(100);
    });

    test("Remise invalide à -5%", () => {
        expect(() => calculerPrix(100, -5)).toThrow("La remise doit être entre 0 et 100");
        //     ↑ ici on garde () => parce qu'on attend une erreur
    });

});