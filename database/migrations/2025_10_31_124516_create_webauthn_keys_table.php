<?php

use Illuminate\Database\ConnectionResolverInterface as Resolver;
use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        if (! Schema::hasTable('webauthn_keys')) {
            Schema::create('webauthn_keys', function (Blueprint $table) {
                $table->id();
                $table->bigInteger('user_id')->unsigned();

                $table->string('name')->default('key');

                $table->binary('credentialId');

                $table->longText('credentialPublicKey');
                $table->text('transports');

                $table->longText('attestationType');

                $table->string('aaguid', 32)->nullable();

                $table->text('trustPath');
                $table->bigInteger('counter')->unsigned();

                $table->string('type')->nullable()->after('credentialId');

                $table->timestamps();

                $table->foreign('user_id')->references('id')->on('users')->onDelete('cascade');
            });
        }

        // Add unique constraint if it doesn't exist
        $connection = app(Resolver::class)->connection();
        $driverName = $connection->getDriverName();
        $tableName = 'webauthn_keys';

        if ($driverName === 'mysql') {
            $indexExists = DB::select("SHOW INDEX FROM {$tableName} WHERE Key_name = 'credential_index'");
            if (empty($indexExists)) {
                DB::statement("CREATE UNIQUE INDEX credential_index ON {$tableName}(credentialId(255))");
            }
        } else {
            // For PostgreSQL, SQLite, etc.
            try {
                Schema::table($tableName, function (Blueprint $table) {
                    $table->unique('credentialId', 'credential_index');
                });
            } catch (\Exception $e) {
                // Index might already exist, ignore
                if (strpos($e->getMessage(), 'already exists') === false &&
                    strpos($e->getMessage(), 'duplicate') === false) {
                    throw $e;
                }
            }
        }
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('webauthn_keys');
    }
};
