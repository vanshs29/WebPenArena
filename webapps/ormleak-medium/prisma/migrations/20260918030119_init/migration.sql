-- CreateTable
CREATE TABLE "User" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "username" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT NOT NULL,
    "role" TEXT NOT NULL DEFAULT 'member',
    "department" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "salary" INTEGER NOT NULL,
    "resetToken" TEXT NOT NULL
);

-- CreateTable
CREATE TABLE "ScoringEvent" (
    "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
    "metric" TEXT NOT NULL,
    "detail" TEXT,
    "ts" REAL NOT NULL
);

-- CreateIndex
CREATE UNIQUE INDEX "User_username_key" ON "User"("username");

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");
