/*
  Warnings:

  - A unique constraint covering the columns `[mfa_secret]` on the table `users` will be added. If there are existing duplicate values, this will fail.

*/
-- AlterTable
ALTER TABLE "users" ADD COLUMN     "mfa_secret" TEXT;

-- CreateIndex
CREATE UNIQUE INDEX "users_mfa_secret_key" ON "users"("mfa_secret");
