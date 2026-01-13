-- AlterTable
ALTER TABLE "password_resets" ADD COLUMN     "used" BOOLEAN NOT NULL DEFAULT false;
