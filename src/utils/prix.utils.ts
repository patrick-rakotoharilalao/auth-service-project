export function calculerPrix(prixBase: number, remise: number): number {
    if (remise < 0 || remise > 100) {
        throw new Error("La remise doit être entre 0 et 100");
    }
    return prixBase - (prixBase * remise / 100);
}