<?php

namespace r0073rr0r\WebAuthn\Models;

use Illuminate\Database\Eloquent\Model;

/**
 * @property int $id
 * @property int $user_id
 * @property string $name
 * @property string $credentialId
 * @property string $credentialPublicKey
 * @property string $transports
 * @property string $attestationType
 * @property string|null $aaguid
 * @property string $trustPath
 * @property int $counter
 * @property \Illuminate\Support\Carbon|null $created_at
 * @property \Illuminate\Support\Carbon|null $updated_at
 * @property string|null $type
 * @property-read \App\Models\User $user
 *
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey newModelQuery()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey newQuery()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey query()
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereAaguid($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereAttestationType($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereCounter($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereCreatedAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereCredentialId($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereCredentialPublicKey($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereId($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereName($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereTransports($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereTrustPath($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereType($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereUpdatedAt($value)
 * @method static \Illuminate\Database\Eloquent\Builder<static>|WebAuthnKey whereUserId($value)
 *
 * @mixin \Eloquent
 */
class WebAuthnKey extends Model
{
    protected $table = 'webauthn_keys';

    protected $fillable = [
        'user_id',
        'name',
        'credentialId',
        'type',
        'transports',
        'attestationType',
        'trustPath',
        'aaguid',
        'credentialPublicKey',
        'counter',
    ];

    public function user(): \Illuminate\Database\Eloquent\Relations\BelongsTo
    {
        $userClass = config('webauthn.user', \App\Models\User::class);
        return $this->belongsTo($userClass);
    }
}
