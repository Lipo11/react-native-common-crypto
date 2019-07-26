import { Platform, NativeModules, NativeEventEmitter } from 'react-native';
import FingerprintIdentify from 'react-native-fingerprint-identify';

var RNCommonCrypto = NativeModules.RNCommonCrypto;

const crypto_emitter = new NativeEventEmitter( RNCommonCrypto );

var factorRejects = new Map();

const Fingerprint =
{
	isAvailable: async () =>
	{
		if( ! Fingerprint._fingerprintIdentify ) { Fingerprint._fingerprintIdentify = await FingerprintIdentify.initFingerPrintIdentify().catch( () => false ); }
		Fingerprint._isSensorAvailable = await FingerprintIdentify.isFingerprintAvailable().catch( () => false );

		return Fingerprint._fingerprintIdentify && Fingerprint._isSensorAvailable;
	},
	scan: () =>
	{
		return new Promise( async (resolve, reject) =>
		{
            FingerprintIdentify.startIdentify( status =>
            {
                if ( status.id !== 'ok' ) { crypto_emitter.emit( 'factorStatus', { flow_id: 0, factor: 'fingerprint', status: status } ); }
            })
            .then( resolve )
            .catch( error => { setTimeout( () => { reject( error ); }, 3000 ); });
		});
	},
	cancelScan: () =>
	{
		FingerprintIdentify.cancelIdentify();
	}
};

function flattenJSONtoSign( data )
{
	var flat = '', keys = Object.keys(data).sort();

	for( let key of keys )
	{
		if( key == 'signature' ){ continue; }

		flat += ( flat.length ? ',' : '' ) + JSON.stringify(key) + ':' + ( data[key] === null ? 'null' : JSON.stringify(data[key].toString()) );
	}

	return '{' + flat + '}';
}

function removeWhitespaces( value )
{
	if( !value )
	{
		return value;
	}

	return value.replace(/[\t\n\r]/gm, '').replace(/(-----BEGIN[^-]+-----)/g,'$1\r\n').replace(/(-----END[^-]+-----)/g,'\r\n$1').replace(/(-----END[^-]+-----)(-----BEGIN[^-]+-----)/g,'$1\r\n$2');
}

const Crypto = module.exports =
{
	emitter: crypto_emitter,
	fetch: async function( url, data, options )
	{
		return RNExcaliburCrypto.fetch(url, JSON.stringify(data), options);
	},
	//Factors EC keys
	_getFactorPublicKey: async function( factor, intent, text, data, resolve, reject )
	{
		try
		{
			factorRejects.set( factor, reject );

			if( factor === 'fingerprint' && Platform.OS === 'android' ){ await Fingerprint.scan(); }

			let result = await RNExcaliburCrypto.getFactorPublicKey(factor, ( typeof intent == 'string' ? intent : flattenJSONtoSign(intent) ), text, ( typeof data == 'string' ? data : Boolean(data) ? flattenJSONtoSign(data) : '' ));

			if( result[factor] && typeof result[factor] == 'string' ){ result[factor] = JSON.parse(result[factor]); }

			result['public-key'] = removeWhitespaces(result['public-key']);
			result.signature = removeWhitespaces(result.signature);

			if( result[factor] ){ result[factor].signature = removeWhitespaces(result[factor].signature); }

			resolve( result );
		}
		catch( e )
		{
			let activeReject = factorRejects.get( factor );
			if( activeReject ){ activeReject( e ); }
		}
		finally
		{
			factorRejects.delete( factor );
		}
	},
	getFactorPublicKey: function( factor, intent, text, data = '' )
	{
		return new Promise( async (resolve, reject) =>
		{
			Crypto._getFactorPublicKey( factor, intent, text, data, resolve, reject );
		});
	},
	_signWithFactor: async function( factor, intent, text, data, resolve, reject )
	{
		try
		{
			factorRejects.set( factor, reject );

			if( factor === 'fingerprint' && Platform.OS === 'android' ){ await Fingerprint.scan(); }

			let result = await RNExcaliburCrypto.signWithFactor(factor, ( typeof intent == 'string' ? intent : flattenJSONtoSign(intent) ), text, ( typeof data == 'string' ? data : Boolean(data) ? flattenJSONtoSign(data) : '' ));

			if( result[factor] && typeof result[factor] == 'string' ){ result[factor] = JSON.parse(result[factor]); }

			result.signature = removeWhitespaces(result.signature);

			if( result[factor] ){ result[factor].signature = removeWhitespaces(result[factor].signature); }

			resolve( result );
		}
		catch( e )
		{
			let activeReject = factorRejects.get( factor );
			if( activeReject ){ activeReject( e ); }
		}
		finally
		{
			factorRejects.delete( factor );
		}
	},
	signWithFactor: function( factor, intent, text, data = '' )
	{
		return new Promise( async (resolve, reject) =>
		{
			Crypto._signWithFactor( factor, intent, text, data, resolve, reject );
		});
	},
	cancelFactor: function( factor )
	{
		if( factorRejects.has( factor ) )
		{
			factorRejects.get( factor )( 'canceled' );
			factorRejects.delete( factor );
		}

		if( factor === 'fingerprint' && Platform.OS === 'android' )
		{
			Fingerprint.cancelScan();
		}

		return RNExcaliburCrypto.cancelFactor(factor);
	},
	//Public actions
	publicEncrypt: function( publicKey, data, format = 'string' )
	{
		return RNExcaliburCrypto.publicEncrypt(publicKey, data, format).then( removeWhitespaces );
	},
	aesEncrypt: function( key, data, auth, iv = '' )
	{
		return RNExcaliburCrypto.aesEncrypt(key, data, auth, iv).then( removeWhitespaces );
	},
	aesDecrypt: function( key, data, auth, iv = '' )
	{
		return RNExcaliburCrypto.aesDecrypt(key, data, auth, iv);
	},
	sha256: function( data )
	{
		return RNExcaliburCrypto.sha256(data);
	},
	generateCSR: function( companyID, deviceID, deviceType = 'token' )
	{
		return RNExcaliburCrypto.generateCSR( companyID.toString(), deviceID.toString(), deviceType );
	}
};
