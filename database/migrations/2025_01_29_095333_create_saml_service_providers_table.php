<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('saml_service_providers', function (Blueprint $table) {
            $table->id();
            $table->string('acs_url_encoded');
            $table->string('acs_url');
            $table->string('destination');
            $table->string('logout');
            $table->longText('certificate');
            $table->boolean('query_params');
            $table->boolean('encrypt_assertion');
            $table->timestamps();

            $table->index('acs_url_encoded');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('saml_service_providers');
    }
};
