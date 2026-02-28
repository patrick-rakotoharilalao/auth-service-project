-- CreateTable
CREATE TABLE "applications" (
    "id" TEXT NOT NULL DEFAULT gen_random_uuid(),
    "name" TEXT NOT NULL,
    "description" TEXT,
    "api_key" TEXT NOT NULL,
    "allowed_origins" TEXT[],
    "webhook_url" TEXT,
    "is_active" BOOLEAN NOT NULL DEFAULT true,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "applications_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "user_app_access" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "applicationId" TEXT NOT NULL,
    "role" TEXT,

    CONSTRAINT "user_app_access_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "applications_api_key_key" ON "applications"("api_key");

-- CreateIndex
CREATE UNIQUE INDEX "user_app_access_userId_applicationId_key" ON "user_app_access"("userId", "applicationId");

-- AddForeignKey
ALTER TABLE "user_app_access" ADD CONSTRAINT "user_app_access_userId_fkey" FOREIGN KEY ("userId") REFERENCES "users"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "user_app_access" ADD CONSTRAINT "user_app_access_applicationId_fkey" FOREIGN KEY ("applicationId") REFERENCES "applications"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
