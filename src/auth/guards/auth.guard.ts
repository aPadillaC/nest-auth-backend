import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from '../interface/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(

    private authService: AuthService,
    private jwtService: JwtService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {

    // Tengo toda la info de la solicutud, url,token....
    const request = context.switchToHttp().getRequest();

    const token = this.extractTokenFromHeader(request);

    // Evaluamos si hay token o no
    if (!token) {
      throw new UnauthorizedException('There is not bearer token');
    }


    try {

      // Comparamos el token para ver si es valido o no, Si es valido guardamos 
      // la informnación descodificada del token en la variable payload
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token, { secret: process.env.JWT_SEED }
        );
  
        console.log({payload});
  
        // Obtengo todos los parámetros del usuario que tiene ese id
        const user = await this.authService.findUserByid( payload.id);

        if (!user) throw new UnauthorizedException('User doesn´t exists');
        if (!user.isActive) throw new UnauthorizedException('User isnt´t active');

        // envío el valor del usuario
        request['user'] = user;
      
    } catch (error) {
      
      throw new UnauthorizedException();
    }

    
      
    return true;
  }


  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }
}
