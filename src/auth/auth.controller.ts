import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateUserDto, UpdateUserDto, LoginDto, RegisterUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';
import { LoginResponse } from './interface/login-response';



@Controller('auth')
export class AuthController {

  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto) {
    return this.authService.create(createUserDto);
  }


  @Post('/login')
  login(@Body() loginUserDto: LoginDto) {
    return this.authService.login(loginUserDto);
  }


  @Post('/register')
  register(@Body() registerUserDto: RegisterUserDto) {
    return this.authService.register(registerUserDto);
  }


  @UseGuards( AuthGuard )
  @Get()
  findAll( @Request() req: Request) {

    return this.authService.findAll();
    
  }


  // actualizar el token
  
  @UseGuards( AuthGuard )
  @Get('check-token')
  // @Request() capturo el valor enviado desde el guard
  checkToken(  @Request() req: Request ): LoginResponse {

    // Asigno a user el valor de la propiedad user de req
    const user = req['user'] as User;

    return {
      user: user,
      token: this.authService.getJwtToken( {id: user._id } )
    };

  }


  // @Get(':id')
  // findOne(@Param('id') id: string) {
  //   return this.authService.findOne(+id);
  // }

  // @Patch(':id')
  // update(@Param('id') id: string, @Body() updateAuthDto: UpdateUserDto) {
  //   return this.authService.update(+id, updateAuthDto);
  // }

  // @Delete(':id')
  // remove(@Param('id') id: string) {
  //   return this.authService.remove(+id);
  // }
}
