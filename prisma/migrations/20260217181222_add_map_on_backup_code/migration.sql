/*
  Warnings:

  - You are about to drop the `BackupCode` table. If the table is not empty, all the data it contains will be lost.

*/
-- DropForeignKey
ALTER TABLE "BackupCode" DROP CONSTRAINT "BackupCode_user_id_fkey";

-- DropTable
DROP TABLE "BackupCode";

-- CreateTable
CREATE TABLE "backup_codes" (
    "id" TEXT NOT NULL DEFAULT gen_random_uuid(),
    "user_id" TEXT NOT NULL,
    "code_hash" TEXT NOT NULL,
    "used" BOOLEAN NOT NULL DEFAULT false,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "backup_codes_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "backup_codes_user_id_idx" ON "backup_codes"("user_id");

-- CreateIndex
CREATE UNIQUE INDEX "backup_codes_code_hash_key" ON "backup_codes"("code_hash");

-- AddForeignKey
ALTER TABLE "backup_codes" ADD CONSTRAINT "backup_codes_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;
