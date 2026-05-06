#!/bin/bash

# Test script for database connections
echo "🧪 Testing Database Connections"
echo "================================"

BASE_URL="http://localhost"

# Check if jq is available for pretty printing
if command -v jq &> /dev/null; then
    PRETTY_PRINT="jq ."
else
    PRETTY_PRINT="cat"
    echo "💡 Tip: Install 'jq' for better JSON formatting: sudo apt install jq"
fi

# Test SQLite connection
echo "Testing SQLite connection..."
curl -s -X POST $BASE_URL/api/db/connect \
  -H "Content-Type: application/json" \
  -d '{"dbType": "sqlite", "connectionString": "/tmp/test.db"}' | $PRETTY_PRINT

echo -e "\nTesting SQLite with non-existent file..."
curl -s -X POST $BASE_URL/api/db/connect \
  -H "Content-Type: application/json" \
  -d '{"dbType": "sqlite", "connectionString": "/tmp/nonexistent.db"}' | $PRETTY_PRINT

echo -e "\nTesting PostgreSQL connection (should fail)..."
curl -s -X POST $BASE_URL/api/db/connect \
  -H "Content-Type: application/json" \
  -d '{"dbType": "postgres", "connectionString": "postgresql://invalid:invalid@nonexistent:5432/test"}' | $PRETTY_PRINT

echo -e "\nTesting MySQL connection (should fail)..."
curl -s -X POST $BASE_URL/api/db/connect \
  -H "Content-Type: application/json" \
  -d '{"dbType": "mysql", "connectionString": "", "config": {"host": "invalid", "user": "test", "password": "test", "database": "test"}}' | $PRETTY_PRINT

echo -e "\n✅ Tests completed!"