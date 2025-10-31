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

        if (app(Resolver::class)->connection()->getDriverName() === 'mysql') {
            DB::statement('CREATE INDEX credential_index ON webauthn_keys(credentialId(255))');
        } else {
            Schema::table('webauthn_keys', function (Blueprint $table) {
                $table->index('credentialId', 'credential_index');
            });
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
