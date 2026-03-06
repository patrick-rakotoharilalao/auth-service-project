/*
  Warnings:

  - You are about to drop the column `applicationId` on the `user_app_access` table. All the data in the column will be lost.
  - You are about to drop the column `userId` on the `user_app_access` table. All the data in the column will be lost.
  - A unique constraint covering the columns `[user_id,application_id]` on the table `user_app_access` will be added. If there are existing duplicate values, this will fail.
  - Added the required column `application_id` to the `user_app_access` table without a default value. This is not possible if the table is not empty.
  - Added the required column `user_id` to the `user_app_access` table without a default value. This is not possible if the table is not empty.

*/
-- DropForeignKey
ALTER TABLE "user_app_access" DROP CONSTRAINT "user_app_access_applicationId_fkey";

-- DropForeignKey
ALTER TABLE "user_app_access" DROP CONSTRAINT "user_app_access_userId_fkey";

-- DropIndex
DROP INDEX "user_app_access_userId_applicationId_key";

-- AlterTable
ALTER TABLE "user_app_access" DROP COLUMN "applicationId",
DROP COLUMN "userId",
ADD COLUMN     "application_id" TEXT NOT NULL,
ADD COLUMN     "user_id" TEXT NOT NULL;

-- CreateIndex
CREATE UNIQUE INDEX "user_app_access_user_id_application_id_key" ON "user_app_access"("user_id", "application_id");

-- AddForeignKey
ALTER TABLE "user_app_access" ADD CONSTRAINT "user_app_access_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_app_access" ADD CONSTRAINT "user_app_access_application_id_fkey" FOREIGN KEY ("application_id") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
